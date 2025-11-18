package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"patchmon-agent/internal/client"
	"patchmon-agent/internal/integrations"
	"patchmon-agent/internal/integrations/docker"
	"patchmon-agent/pkg/models"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

// serveCmd runs the agent as a long-lived service
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the agent as a service with async updates",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkRoot(); err != nil {
			return err
		}
		return runService()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runService() error {
	if err := cfgManager.LoadCredentials(); err != nil {
		return err
	}

	httpClient := client.New(cfgManager, logger)
	ctx := context.Background()

	// obtain initial interval
	intervalMinutes := 60
	if resp, err := httpClient.GetUpdateInterval(ctx); err == nil && resp.UpdateInterval > 0 {
		intervalMinutes = resp.UpdateInterval
	}

	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
	defer ticker.Stop()

	// Send startup ping to notify server that agent has started
	logger.Info("🚀 Agent starting up, notifying server...")
	if _, err := httpClient.Ping(ctx); err != nil {
		logger.WithError(err).Warn("startup ping failed, will retry")
	} else {
		logger.Info("✅ Startup notification sent to server")
	}

	// initial report on boot
	logger.Info("Sending initial report on startup...")
	if err := sendReport(); err != nil {
		logger.WithError(err).Warn("initial report failed")
	} else {
		logger.Info("✅ Initial report sent successfully")
	}

	// start websocket loop
	logger.Info("Establishing WebSocket connection...")
	messages := make(chan wsMsg, 10)
	dockerEvents := make(chan interface{}, 100)
	go wsLoop(messages, dockerEvents)

	// Start integration monitoring (Docker real-time events, etc.)
	startIntegrationMonitoring(ctx, dockerEvents)

	for {
		select {
		case <-ticker.C:
			if err := sendReport(); err != nil {
				logger.WithError(err).Warn("periodic report failed")
			}
		case m := <-messages:
			switch m.kind {
			case "settings_update":
				if m.interval > 0 {
					ticker.Stop()
					ticker = time.NewTicker(time.Duration(m.interval) * time.Minute)
					logger.WithField("new_interval", m.interval).Info("interval updated, no report sent")
				}
			case "report_now":
				if err := sendReport(); err != nil {
					logger.WithError(err).Warn("report_now failed")
				}
			case "update_agent":
				if err := updateAgent(); err != nil {
					logger.WithError(err).Warn("update_agent failed")
				}
			case "update_notification":
				logger.WithField("version", m.version).Info("Update notification received from server")
				if m.force {
					logger.Info("Force update requested, updating agent now")
					if err := updateAgent(); err != nil {
						logger.WithError(err).Warn("forced update failed")
					}
				} else {
					logger.Info("Update available, run 'patchmon-agent update-agent' to update")
				}
			case "integration_toggle":
				if err := toggleIntegration(m.integrationName, m.integrationEnabled); err != nil {
					logger.WithError(err).Warn("integration_toggle failed")
				} else {
					logger.WithFields(map[string]interface{}{
						"integration": m.integrationName,
						"enabled":     m.integrationEnabled,
					}).Info("Integration toggled successfully, service will restart")
				}
			}
		}
	}
}

// startIntegrationMonitoring starts real-time monitoring for integrations that support it
func startIntegrationMonitoring(ctx context.Context, eventChan chan<- interface{}) {
	// Create integration manager
	integrationMgr := integrations.NewManager(logger)

	// Set enabled checker to respect config.yml settings
	integrationMgr.SetEnabledChecker(func(name string) bool {
		return cfgManager.IsIntegrationEnabled(name)
	})

	// Register integrations
	dockerInteg := docker.New(logger)
	integrationMgr.Register(dockerInteg)

	// Start monitoring for real-time integrations
	realtimeIntegrations := integrationMgr.GetRealtimeIntegrations()
	for _, integration := range realtimeIntegrations {
		logger.WithField("integration", integration.Name()).Info("Starting real-time monitoring")

		// Start monitoring in a goroutine
		go func(integ integrations.RealtimeIntegration) {
			if err := integ.StartMonitoring(ctx, eventChan); err != nil {
				logger.WithError(err).Warn("Failed to start integration monitoring")
			}
		}(integration)
	}
}

type wsMsg struct {
	kind               string
	interval           int
	version            string
	force              bool
	integrationName    string
	integrationEnabled bool
}

func wsLoop(out chan<- wsMsg, dockerEvents <-chan interface{}) {
	backoff := time.Second
	for {
		if err := connectOnce(out, dockerEvents); err != nil {
			logger.WithError(err).Warn("ws disconnected; retrying")
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func connectOnce(out chan<- wsMsg, dockerEvents <-chan interface{}) error {
	server := cfgManager.GetConfig().PatchmonServer
	if server == "" {
		return nil
	}
	apiID := cfgManager.GetCredentials().APIID
	apiKey := cfgManager.GetCredentials().APIKey

	// Convert http(s) -> ws(s)
	wsURL := server
	if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	} else if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	} else if strings.HasPrefix(wsURL, "wss://") {
		// Already a WebSocket secure URL, use as-is
		// No conversion needed
	} else if strings.HasPrefix(wsURL, "ws://") {
		// Already a WebSocket URL, use as-is
		// No conversion needed
	} else {
		// No protocol prefix - assume HTTPS and use WSS
		logger.WithField("server", server).Warn("Server URL missing protocol prefix, assuming HTTPS")
		wsURL = "wss://" + wsURL
	}
	if strings.HasSuffix(wsURL, "/") {
		wsURL = strings.TrimRight(wsURL, "/")
	}
	wsURL = wsURL + "/api/" + cfgManager.GetConfig().APIVersion + "/agents/ws"
	header := http.Header{}
	header.Set("X-API-ID", apiID)
	header.Set("X-API-KEY", apiKey)

	// Configure WebSocket dialer for insecure connections if needed
	dialer := websocket.DefaultDialer
	if cfgManager.GetConfig().SkipSSLVerify {
		dialer = &websocket.Dialer{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		logger.Warn("⚠️  SSL certificate verification is disabled for WebSocket")
	}

	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// ping loop
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			_ = conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
		}
	}()

	// Set read deadlines and extend them on pong frames to avoid idle timeouts
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	})

	logger.WithField("url", wsURL).Info("WebSocket connected")

	// Create a goroutine to send Docker events through WebSocket
	go func() {
		for event := range dockerEvents {
			if dockerEvent, ok := event.(models.DockerStatusEvent); ok {
				eventJSON, err := json.Marshal(map[string]interface{}{
					"type":         "docker_status",
					"event":        dockerEvent,
					"container_id": dockerEvent.ContainerID,
					"name":         dockerEvent.Name,
					"status":       dockerEvent.Status,
					"timestamp":    dockerEvent.Timestamp,
				})
				if err != nil {
					logger.WithError(err).Warn("Failed to marshal Docker event")
					continue
				}

				if err := conn.WriteMessage(websocket.TextMessage, eventJSON); err != nil {
					logger.WithError(err).Debug("Failed to send Docker event via WebSocket")
					return
				}
			}
		}
	}()

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var payload struct {
			Type           string `json:"type"`
			UpdateInterval int    `json:"update_interval"`
			Version        string `json:"version"`
			Force          bool   `json:"force"`
			Message        string `json:"message"`
			Integration    string `json:"integration"`
			Enabled        bool   `json:"enabled"`
		}
		if json.Unmarshal(data, &payload) == nil {
			switch payload.Type {
			case "settings_update":
				logger.WithField("interval", payload.UpdateInterval).Info("settings_update received")
				out <- wsMsg{kind: "settings_update", interval: payload.UpdateInterval}
			case "report_now":
				logger.Info("report_now received")
				out <- wsMsg{kind: "report_now"}
			case "update_agent":
				logger.Info("update_agent received")
				out <- wsMsg{kind: "update_agent"}
			case "update_notification":
				logger.WithFields(map[string]interface{}{
					"version": payload.Version,
					"force":   payload.Force,
					"message": payload.Message,
				}).Info("update_notification received")
				out <- wsMsg{
					kind:    "update_notification",
					version: payload.Version,
					force:   payload.Force,
				}
			case "integration_toggle":
				logger.WithFields(map[string]interface{}{
					"integration": payload.Integration,
					"enabled":     payload.Enabled,
				}).Info("integration_toggle received")
				out <- wsMsg{
					kind:               "integration_toggle",
					integrationName:    payload.Integration,
					integrationEnabled: payload.Enabled,
				}
			}
		}
	}
}

// toggleIntegration toggles an integration on or off and restarts the service
func toggleIntegration(integrationName string, enabled bool) error {
	logger.WithFields(map[string]interface{}{
		"integration": integrationName,
		"enabled":     enabled,
	}).Info("Toggling integration")

	// Update config.yml
	if err := cfgManager.SetIntegrationEnabled(integrationName, enabled); err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	logger.Info("Config updated, restarting patchmon-agent service...")

	// Restart the service to apply changes (supports systemd and OpenRC)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := exec.LookPath("systemctl"); err == nil {
		// Systemd is available
		logger.Debug("Detected systemd, using systemctl restart")
		cmd := exec.CommandContext(ctx, "systemctl", "restart", "patchmon-agent")
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger.WithError(err).Warn("Failed to restart service (this is not critical)")
			return fmt.Errorf("failed to restart service: %w, output: %s", err, string(output))
		}
		logger.WithField("output", string(output)).Debug("Service restart command completed")
		logger.Info("Service restarted successfully")
		return nil
	} else if _, err := exec.LookPath("rc-service"); err == nil {
		// OpenRC is available (Alpine Linux)
		// Since we're running inside the service, we can't stop ourselves directly
		// Instead, we'll create a helper script that runs after we exit
		logger.Debug("Detected OpenRC, scheduling service restart via helper script")
		
		// Create a helper script that will restart the service after we exit
		helperScript := `#!/bin/sh
# Wait a moment for the current process to exit
sleep 2
# Restart the service
rc-service patchmon-agent restart 2>&1 || rc-service patchmon-agent start 2>&1
# Clean up this script
rm -f "$0"
`
		helperPath := "/etc/patchmon/patchmon-restart-helper.sh"
		if err := os.WriteFile(helperPath, []byte(helperScript), 0755); err != nil {
			logger.WithError(err).Warn("Failed to create restart helper script, will exit and rely on OpenRC auto-restart")
			// Fall through to exit approach
		} else {
			// Execute the helper script in background (detached from current process)
			// Use 'sh -c' with nohup to ensure it runs after we exit
			cmd := exec.Command("sh", "-c", fmt.Sprintf("nohup %s > /dev/null 2>&1 &", helperPath))
			if err := cmd.Start(); err != nil {
				logger.WithError(err).Warn("Failed to start restart helper script, will exit and rely on OpenRC auto-restart")
				// Clean up script
				if removeErr := os.Remove(helperPath); removeErr != nil {
					logger.WithError(removeErr).Debug("Failed to remove helper script")
				}
				// Fall through to exit approach
			} else {
				logger.Info("Scheduled service restart via helper script, exiting now...")
				// Give the helper script a moment to start
				time.Sleep(500 * time.Millisecond)
				// Exit gracefully - the helper script will restart the service
				os.Exit(0)
			}
		}
		
		// Fallback: If helper script approach failed, just exit and let OpenRC handle it
		// OpenRC with command_background="yes" should restart on exit
		logger.Info("Exiting to allow OpenRC to restart service with updated config...")
		os.Exit(0)
		// os.Exit never returns, but we need this for code flow
		return nil
	} else {
		logger.Warn("No known init system detected, attempting to restart via process signal")
		// Try to find and kill the process, service manager should restart it
		killCmd := exec.CommandContext(ctx, "pkill", "-HUP", "patchmon-agent")
		if err := killCmd.Run(); err != nil {
			logger.WithError(err).Warn("Failed to restart service (this is not critical)")
			return fmt.Errorf("failed to restart service: no init system detected and pkill failed: %w", err)
		}
		logger.Info("Sent HUP signal to agent process")
		return nil
	}
}
