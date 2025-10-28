package docker

import (
	"context"
	"fmt"
	"time"

	"patchmon-agent/pkg/models"

	"github.com/docker/docker/api/types/events"
	"github.com/sirupsen/logrus"
)

// StartMonitoring begins monitoring Docker events for real-time status changes
func (d *Integration) StartMonitoring(ctx context.Context, eventChan chan<- interface{}) error {
	d.monitoringMu.Lock()
	if d.monitoring {
		d.monitoringMu.Unlock()
		return fmt.Errorf("monitoring already started")
	}
	d.monitoring = true
	d.monitoringMu.Unlock()

	if d.client == nil {
		if !d.IsAvailable() {
			return fmt.Errorf("docker is not available")
		}
	}

	// Create a cancellable context
	monitorCtx, cancel := context.WithCancel(ctx)
	d.stopMonitoring = cancel

	d.logger.Info("Starting Docker event monitoring...")

	// Start listening for Docker events
	eventsCh, errCh := d.client.Events(monitorCtx, events.ListOptions{})

	// Process events in a goroutine
	go d.processEvents(monitorCtx, eventsCh, errCh, eventChan)

	return nil
}

// StopMonitoring stops Docker event monitoring
func (d *Integration) StopMonitoring() error {
	d.monitoringMu.Lock()
	defer d.monitoringMu.Unlock()

	if !d.monitoring {
		return nil
	}

	if d.stopMonitoring != nil {
		d.stopMonitoring()
		d.stopMonitoring = nil
	}

	d.monitoring = false
	d.logger.Info("Stopped Docker event monitoring")

	return nil
}

// processEvents processes Docker events and sends relevant ones to the event channel
func (d *Integration) processEvents(ctx context.Context, eventsCh <-chan events.Message, errCh <-chan error, eventChan chan<- interface{}) {
	defer func() {
		d.monitoringMu.Lock()
		d.monitoring = false
		d.monitoringMu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			d.logger.Debug("Docker event monitoring context cancelled")
			return

		case err := <-errCh:
			if err != nil {
				d.logger.WithError(err).Error("Docker event error")
				// Try to reconnect after a delay
				time.Sleep(5 * time.Second)
				continue
			}

		case event := <-eventsCh:
			if event.Type == events.ContainerEventType {
				d.handleContainerEvent(event, eventChan)
			}
		}
	}
}

// handleContainerEvent processes container events and sends status updates
func (d *Integration) handleContainerEvent(event events.Message, eventChan chan<- interface{}) {
	// We're interested in these actions:
	// - start: container started
	// - stop: container stopped
	// - die: container died (crashed)
	// - pause: container paused
	// - unpause: container unpaused
	// - kill: container killed
	// - destroy: container destroyed

	relevantActions := map[string]string{
		"start":   "container_start",
		"stop":    "container_stop",
		"die":     "container_die",
		"pause":   "container_pause",
		"unpause": "container_unpause",
		"kill":    "container_kill",
		"destroy": "container_destroy",
	}

	eventType, relevant := relevantActions[string(event.Action)]
	if !relevant {
		return
	}

	// Extract container information
	containerID := event.Actor.ID
	containerName := ""
	image := ""

	// Get name from attributes
	if name, ok := event.Actor.Attributes["name"]; ok {
		containerName = name
	}

	// Get image from attributes
	if img, ok := event.Actor.Attributes["image"]; ok {
		image = img
	}

	// Determine status based on action
	status := mapActionToStatus(string(event.Action))

	statusEvent := models.DockerStatusEvent{
		Type:        eventType,
		ContainerID: containerID,
		Name:        containerName,
		Image:       image,
		Status:      status,
		Timestamp:   time.Unix(event.Time, 0),
	}

	d.logger.WithFields(logrus.Fields{
		"type":         eventType,
		"container_id": containerID[:12], // Short ID
		"name":         containerName,
		"image":        image,
		"status":       status,
	}).Info("Docker container event")

	// Send event to channel (non-blocking)
	select {
	case eventChan <- statusEvent:
	default:
		d.logger.Warn("Event channel full, dropping event")
	}
}

// mapActionToStatus maps Docker event actions to status strings
func mapActionToStatus(action string) string {
	switch action {
	case "start":
		return "running"
	case "stop", "die", "kill":
		return "exited"
	case "pause":
		return "paused"
	case "unpause":
		return "running"
	case "destroy":
		return "removed"
	default:
		return "unknown"
	}
}
