/**
 * CyberShield Dashboard JavaScript
 * Real-time WebSocket-based dashboard updates with expandable modals
 */

class CyberShieldDashboard {
    constructor(apiKey = null) {
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 2000;
        this.isConnected = false;
        this.shouldReconnect = false;
        this.apiKey = apiKey || this.getApiKeyFromStorage();

        // Store data for expandable views
        this.data = {
            alerts: [],
            threats: [],
            agents: [],
            components: {},
            metrics: {},
            agentActions: [],
            escalatedThreats: []
        };

        // Initialize
        this.init();
    }

    getApiKeyFromStorage() {
        const urlParams = new URLSearchParams(window.location.search);
        const urlKey = urlParams.get('api_key');
        if (urlKey) {
            localStorage.setItem('cybershield_api_key', urlKey);
            return urlKey;
        }
        return localStorage.getItem('cybershield_api_key') || '';
    }

    setApiKey(key) {
        this.apiKey = key;
        localStorage.setItem('cybershield_api_key', key);
    }

    init() {
        this.startClock();
        this.setupEventListeners();
        this.setupAuthUI();
        this.setupModal();
        this.setupExpandableClicks();

        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('api_key')) {
            this.shouldReconnect = true;
            this.connectWebSocket();
        } else if (this.apiKey) {
            document.getElementById('apiKeyInput').value = this.apiKey;
        }
    }

    // Modal Setup
    setupModal() {
        // Create modal overlay
        const modal = document.createElement('div');
        modal.id = 'modalOverlay';
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3 id="modalTitle">Details</h3>
                    <button class="modal-close" onclick="dashboard.closeModal()">&times;</button>
                </div>
                <div class="modal-body" id="modalBody"></div>
            </div>
        `;
        document.body.appendChild(modal);

        // Close on overlay click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) this.closeModal();
        });

        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeModal();
        });
    }

    openModal(title, content) {
        document.getElementById('modalTitle').textContent = title;
        document.getElementById('modalBody').innerHTML = content;
        document.getElementById('modalOverlay').classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    closeModal() {
        document.getElementById('modalOverlay').classList.remove('active');
        document.body.style.overflow = '';
    }

    setupExpandableClicks() {
        // Expansion is now handled by dedicated expand buttons in HTML
        // No click handlers on titles anymore
    }

    // Toggle section expand/collapse
    toggleSection(sectionId) {
        const section = document.getElementById(sectionId);
        if (!section) return;
        section.classList.toggle('collapsed');
    }

    expandAlerts() {
        const content = this.data.alerts.length === 0
            ? '<p style="color: var(--text-secondary);">No alerts to display</p>'
            : `<div class="modal-alerts-list">
                ${this.data.alerts.map(alert => {
                    const title = alert.title || `${(alert.threat_type || 'Unknown').toUpperCase()} Alert`;
                    const summary = alert.summary || `Threat detected from ${alert.source || 'unknown source'}`;
                    const severity = alert.severity || 'medium';
                    return `
                    <div class="modal-alert-item ${severity}">
                        <div class="modal-alert-header">
                            <span class="modal-alert-title">${title}</span>
                            <span class="modal-alert-time">${this.formatTime(alert.timestamp)}</span>
                        </div>
                        <div class="modal-alert-summary">${summary}</div>
                        <div class="modal-alert-meta">
                            <span>Source: ${alert.source || 'Unknown'}</span>
                            <span>Type: ${alert.threat_type || 'Unknown'}</span>
                            <span>Status: ${alert.status || 'Unknown'}</span>
                        </div>
                    </div>
                `}).join('')}
            </div>`;
        this.openModal('Recent Alerts', content);
    }

    expandThreats() {
        const content = this.data.threats.length === 0
            ? '<p style="color: var(--text-secondary);">No active threats</p>'
            : `<table class="modal-threats-table">
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Attack Type</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Detected</th>
                    </tr>
                </thead>
                <tbody>
                    ${this.data.threats.map(t => `
                        <tr>
                            <td>${t.source_ip?.address || 'Unknown'}</td>
                            <td>${t.attack_signature?.attack_type || 'Unknown'}</td>
                            <td><span class="severity ${t.threat_level?.severity || 'medium'}">${t.threat_level?.severity || 'Unknown'}</span></td>
                            <td>${t.status || 'Unknown'}</td>
                            <td>${this.formatTime(t.detected_at)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>`;
        this.openModal('Active Threats', content);
    }

    expandAgents() {
        const content = `<div class="modal-agents-grid">
            ${this.data.agents.map(agent => `
                <div class="modal-agent-card">
                    <div class="modal-agent-header">
                        <span class="modal-agent-name">${this.formatAgentName(agent.type)}</span>
                        <span class="status active">Active</span>
                    </div>
                    <div class="modal-agent-stats">
                        ${Object.entries(agent.stats || {}).map(([key, value]) => `
                            <div class="modal-stat-row">
                                <span class="modal-stat-label">${this.formatStatKey(key)}</span>
                                <span class="modal-stat-value">${value}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('')}
        </div>`;
        this.openModal('Agent Status Details', content);
    }

    expandComponents() {
        const content = `<div class="modal-components-grid">
            ${Object.entries(this.data.components).map(([name, status]) => `
                <div class="modal-component-card">
                    <div class="modal-component-name">${this.formatComponentName(name)}</div>
                    <div class="modal-component-status ${status}">${status}</div>
                </div>
            `).join('')}
        </div>`;
        this.openModal('Component Status Details', content);
    }

    expandAgentActions() {
        const content = this.data.agentActions.length === 0
            ? '<p style="color: var(--text-secondary);">No agent actions recorded yet. Run an attack simulation to see the multi-model response pipeline in action.</p>'
            : `<div class="modal-alerts-list">
                ${this.data.agentActions.map(action => `
                    <div class="modal-alert-item ${action.status === 'success' ? 'low' : action.status === 'failed' ? 'critical' : 'medium'}">
                        <div class="modal-alert-header">
                            <span class="modal-alert-title">${this.formatActionType(action.action_type)} - ${action.agent}</span>
                            <span class="modal-alert-time">${this.formatTime(action.timestamp)}</span>
                        </div>
                        <div class="modal-alert-summary">
                            Target: ${action.target}<br>
                            ${action.details || ''}
                        </div>
                        <div class="modal-alert-meta">
                            <span>Status: ${action.status}</span>
                            <span>Effectiveness: ${action.effectiveness || 'N/A'}</span>
                            <span>Execution Time: ${action.execution_time || 'N/A'}</span>
                        </div>
                    </div>
                `).join('')}
            </div>`;
        this.openModal('Agent Actions - Multi-Model Response Pipeline', content);
    }

    formatStatKey(key) {
        return key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
    }

    formatActionType(actionType) {
        // Convert enum values like "SCAN_AND_ASSESS" to "Scan and Assess"
        if (!actionType) return 'Unknown Action';
        return actionType
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
            .join(' ');
    }

    setupAuthUI() {
        const connectBtn = document.getElementById('connectBtn');
        const apiKeyInput = document.getElementById('apiKeyInput');

        connectBtn.addEventListener('click', () => {
            if (this.isConnected) {
                this.shouldReconnect = false;
                if (this.ws) this.ws.close();
                this.updateAuthUI(false);
            } else {
                const key = apiKeyInput.value.trim();
                if (key) {
                    this.setApiKey(key);
                    this.shouldReconnect = true;
                    this.reconnectAttempts = 0;
                    this.connectWebSocket();
                } else {
                    this.showError('Please enter an API key');
                }
            }
        });

        apiKeyInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') connectBtn.click();
        });
    }

    updateAuthUI(connected) {
        const connectBtn = document.getElementById('connectBtn');
        const apiKeyInput = document.getElementById('apiKeyInput');

        if (connected) {
            connectBtn.textContent = 'Disconnect';
            connectBtn.classList.remove('btn-connect');
            connectBtn.classList.add('btn-disconnect');
            apiKeyInput.disabled = true;
        } else {
            connectBtn.textContent = 'Connect';
            connectBtn.classList.add('btn-connect');
            connectBtn.classList.remove('btn-disconnect');
            apiKeyInput.disabled = false;
        }
    }

    showError(message) {
        const statusText = document.querySelector('#connectionStatus .status-text');
        statusText.textContent = message;
        setTimeout(() => {
            if (!this.isConnected) statusText.textContent = 'Disconnected';
        }, 3000);
    }

    connectWebSocket() {
        if (!this.apiKey) {
            this.showError('API key required');
            return;
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        let wsUrl = `${protocol}//${window.location.host}/ws?api_key=${encodeURIComponent(this.apiKey)}`;

        console.log('Connecting to WebSocket...');
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.updateConnectionStatus(true);
            this.updateAuthUI(true);
        };

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleMessage(message);
        };

        this.ws.onclose = (event) => {
            console.log('WebSocket disconnected', event.code, event.reason);
            this.isConnected = false;
            this.updateConnectionStatus(false);
            this.updateAuthUI(false);

            if (event.code === 4001) {
                this.showError('Invalid API key');
                this.shouldReconnect = false;
            }

            if (this.shouldReconnect) this.attemptReconnect();
        };

        this.ws.onerror = (error) => console.error('WebSocket error:', error);
    }

    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts && this.shouldReconnect) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts - 1);
            document.querySelector('#connectionStatus .status-text').textContent = `Reconnecting (${this.reconnectAttempts})...`;
            setTimeout(() => {
                if (this.shouldReconnect) this.connectWebSocket();
            }, delay);
        } else if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            this.showError('Connection failed');
            this.shouldReconnect = false;
        }
    }

    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connectionStatus');
        const dot = statusElement.querySelector('.status-dot');
        const text = statusElement.querySelector('.status-text');

        if (connected) {
            dot.classList.add('connected');
            dot.classList.remove('disconnected');
            text.textContent = 'Connected';
        } else {
            dot.classList.remove('connected');
            dot.classList.add('disconnected');
            if (!this.shouldReconnect) text.textContent = 'Disconnected';
        }
    }

    handleMessage(message) {
        const { type, data, timestamp } = message;

        switch (type) {
            case 'initial_state':
                this.updateDashboard(data);
                // Load persisted alerts
                if (data.alerts && data.alerts.length > 0) {
                    this.loadPersistedAlerts(data.alerts);
                }
                // Load threats
                if (data.threats && data.threats.length > 0) {
                    this.loadThreats(data.threats);
                }
                // Load agent actions if available
                if (data.agent_actions && data.agent_actions.length > 0) {
                    this.loadAgentActions(data.agent_actions);
                }
                break;
            case 'status_update':
                this.updateDashboard(data);
                break;
            case 'alert':
                // Check if this is an escalation alert
                if (data.type === 'escalation') {
                    this.addEscalatedThreat(data);
                } else {
                    this.addAlert(data);
                    // Extract agent actions from alert if present
                    if (data.actions_taken && data.actions_taken.length > 0) {
                        this.extractAgentActionsFromAlert(data);
                    }
                }
                break;
            case 'threat':
                this.updateThreat(data);
                break;
            case 'threat_removed':
                this.handleThreatRemoved(data.threat_id);
                break;
            case 'agent_action':
                this.addAgentAction(data);
                break;
            case 'event':
                this.handleEvent(data);
                break;
            case 'pong':
                break;
            default:
                console.log('Unknown message type:', type);
        }

        document.getElementById('lastUpdate').textContent = `Last update: ${this.formatTime(timestamp)}`;
    }

    loadPersistedAlerts(alerts) {
        this.data.alerts = alerts;
        const list = document.getElementById('alertsList');
        const noAlerts = list.querySelector('.no-alerts');
        if (noAlerts) noAlerts.remove();

        // Clear existing and add persisted alerts
        list.innerHTML = '';
        alerts.forEach(alert => {
            // Defensive coding for missing fields
            const title = alert.title || `${(alert.threat_type || 'Unknown').toUpperCase()} Alert`;
            const summary = alert.summary || `Threat detected from ${alert.source || 'unknown source'}`;
            const severity = alert.severity || 'medium';

            const item = document.createElement('div');
            item.className = `alert-item ${severity}`;
            item.innerHTML = `
                <div class="alert-content">
                    <div class="alert-title">${title}</div>
                    <div class="alert-summary">${summary}</div>
                </div>
                <div class="alert-time">${this.formatTime(alert.timestamp)}</div>
            `;
            list.appendChild(item);

            // Extract agent actions from alerts
            if (alert.actions_taken && alert.actions_taken.length > 0) {
                this.extractAgentActionsFromAlert(alert);
            }
        });

        if (alerts.length === 0) {
            list.innerHTML = '<div class="no-alerts">No recent alerts</div>';
        }
    }

    loadAgentActions(actions) {
        this.data.agentActions = actions;
        this.renderAgentActions();
    }

    extractAgentActionsFromAlert(alert) {
        // Parse actions_taken strings like "block_ip: 192.168.x.x (success)"
        if (!alert.actions_taken) return;

        alert.actions_taken.forEach(actionStr => {
            const match = actionStr.match(/^(\w+):\s*(.+)\s*\((\w+)\)$/);
            if (match) {
                const action = {
                    action_type: match[1].replace(/_/g, ' ').toUpperCase(),
                    target: match[2].trim(),
                    status: match[3],
                    agent: this.getAgentForActionType(match[1]),
                    timestamp: alert.timestamp,
                    threat_type: alert.threat_type,
                    effectiveness: alert.metrics?.mitigation_time ? '95%' : 'N/A',
                    execution_time: alert.metrics?.mitigation_time || 'N/A',
                    details: `Response to ${alert.threat_type} attack from ${alert.source}`
                };
                this.addAgentAction(action);
            }
        });
    }

    getAgentForActionType(actionType) {
        const agentMap = {
            'block_ip': 'Mitigator Bot',
            'rate_limit': 'Mitigator Bot',
            'drop_connection': 'Mitigator Bot',
            'analyze': 'Analyzer Bot',
            'alert': 'Reporter Bot',
            'monitor': 'Monitor Bot',
            'coordinate': 'Orchestrator'
        };
        return agentMap[actionType] || 'Response Agent';
    }

    addAgentAction(action) {
        // Add to data store
        this.data.agentActions.unshift(action);
        if (this.data.agentActions.length > 100) this.data.agentActions.pop();

        this.renderAgentActions();
    }

    renderAgentActions() {
        const list = document.getElementById('agentActionsList');
        if (!list) return;

        const noActions = list.querySelector('.no-actions');
        if (noActions) noActions.remove();

        // Clear and re-render
        list.innerHTML = '';

        if (this.data.agentActions.length === 0) {
            list.innerHTML = '<div class="no-actions">No recent agent actions</div>';
            return;
        }

        // Show most recent 15 actions
        this.data.agentActions.slice(0, 15).forEach(action => {
            const item = document.createElement('div');
            item.className = 'action-item';
            const shortAgent = action.agent?.split(' ')[0] || 'Agent';
            item.innerHTML = `
                <div class="action-pipeline">
                    <span class="pipeline-arrow">▼</span>
                    <span class="agent-name">${shortAgent}</span>
                </div>
                <div class="action-content">
                    <div class="action-header">
                        <span class="action-type">${this.formatActionType(action.action_type)}</span>
                        <span class="action-status ${action.status}">${action.status}</span>
                    </div>
                    <div class="action-details">
                        ${action.target} • ${action.threat_type || 'Unknown'}
                    </div>
                </div>
            `;
            list.appendChild(item);
        });
    }

    updateDashboard(data) {
        if (data.overall) this.updateOverallStatus(data.overall);
        if (data.metrics) {
            this.data.metrics = data.metrics;
            this.updateMetrics(data.metrics);
        }
        if (data.components) {
            this.data.components = data.components;
            this.updateComponents(data.components);
        }
        if (data.agents) {
            this.data.agents = data.agents;
            this.updateAgents(data.agents);
        }
    }

    updateOverallStatus(status) {
        const element = document.querySelector('#overallStatus .status-value');
        element.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        element.className = 'status-value ' + status;
    }

    updateMetrics(metrics) {
        // Update from orchestrator stats if available
        const activeThreats = metrics.active_threats ?? metrics.threats_active ?? 0;
        const threatsDetected = metrics.threats_detected_total ?? metrics.orchestration_count ?? 0;
        const threatsMitigated = metrics.threats_mitigated_total ?? metrics.success_count ?? 0;
        const successRate = metrics.success_rate ?? 0;

        document.getElementById('activeThreats').textContent = activeThreats;
        document.getElementById('threatsDetected').textContent = threatsDetected;
        document.getElementById('threatsMitigated').textContent = threatsMitigated;
        document.getElementById('successRate').textContent = `${(successRate * 100).toFixed(1)}%`;
    }

    updateComponents(components) {
        const grid = document.getElementById('componentsGrid');
        grid.innerHTML = '';

        for (const [name, status] of Object.entries(components)) {
            const item = document.createElement('div');
            item.className = 'component-item clickable-tile';
            item.innerHTML = `
                <div class="name">${this.formatComponentName(name)}</div>
                <div class="status ${status}">${status}</div>
            `;
            // Click handler for individual component
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                this.openComponentModal(name, status);
            });
            grid.appendChild(item);
        }
    }

    // Open modal for individual component
    openComponentModal(name, status) {
        const content = `
            <div class="component-detail-modal">
                <div class="component-detail-header">
                    <div class="component-icon">${this.getComponentIcon(name)}</div>
                    <div class="component-info">
                        <h3>${this.formatComponentName(name)}</h3>
                        <span class="status-badge ${status}">${status.toUpperCase()}</span>
                    </div>
                </div>
                <div class="component-detail-content">
                    <div class="detail-row">
                        <span class="label">Component ID</span>
                        <span class="value">${name}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Status</span>
                        <span class="value ${status}">${status}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Last Updated</span>
                        <span class="value">${new Date().toLocaleString()}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Health Score</span>
                        <span class="value">${status === 'healthy' ? '100%' : status === 'degraded' ? '75%' : '25%'}</span>
                    </div>
                </div>
            </div>
        `;
        this.openModal(`Component: ${this.formatComponentName(name)}`, content);
    }

    getComponentIcon(name) {
        const icons = {
            'detector': '🔍',
            'orchestrator': '🎯',
            'mitigator': '🛡️',
            'reporter': '📊',
            'cache': '💾',
            'api': '🌐',
            'websocket': '🔌',
            'ml_engine': '🧠',
            'default': '⚙️'
        };
        return icons[name.toLowerCase()] || icons['default'];
    }

    updateAgents(agents) {
        const grid = document.getElementById('agentsGrid');
        grid.innerHTML = '';

        for (const agent of agents) {
            // Get actual status from agent data
            const status = agent.status || 'active';
            const statusClass = status === 'active' || status === 'healthy' ? 'active' :
                               status === 'degraded' ? 'degraded' : 'unresponsive';
            const statusText = status === 'active' || status === 'healthy' ? 'Active' :
                              status.charAt(0).toUpperCase() + status.slice(1);

            const item = document.createElement('div');
            item.className = 'agent-item clickable-tile';
            item.innerHTML = `
                <div class="name">${this.formatAgentName(agent.type)}</div>
                <div class="status ${statusClass}">${statusText}</div>
                <div class="stats">${this.formatAgentStats(agent.stats)}</div>
            `;
            // Click handler for individual agent
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                this.openAgentModal(agent);
            });
            grid.appendChild(item);
        }
    }

    // Open modal for individual agent
    openAgentModal(agent) {
        const status = agent.status || 'active';
        const statusClass = status === 'active' || status === 'healthy' ? 'active' :
                           status === 'degraded' ? 'degraded' : 'unresponsive';
        const statusText = (status === 'active' || status === 'healthy' ? 'ACTIVE' :
                          status.toUpperCase());

        const content = `
            <div class="agent-detail-modal">
                <div class="agent-detail-header">
                    <div class="agent-icon">${this.getAgentIcon(agent.type)}</div>
                    <div class="agent-info">
                        <h3>${this.formatAgentName(agent.type)}</h3>
                        <span class="status-badge ${statusClass}">${statusText}</span>
                    </div>
                </div>
                <div class="agent-detail-content">
                    <h4>Agent Statistics</h4>
                    <div class="stats-grid">
                        ${Object.entries(agent.stats || {}).map(([key, value]) => `
                            <div class="stat-item">
                                <span class="stat-label">${this.formatStatKey(key)}</span>
                                <span class="stat-value">${value}</span>
                            </div>
                        `).join('')}
                    </div>
                    <h4>Agent Capabilities</h4>
                    <div class="capabilities-list">
                        ${this.getAgentCapabilities(agent.type).map(cap => `
                            <div class="capability-item">✓ ${cap}</div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
        this.openModal(`Agent: ${this.formatAgentName(agent.type)}`, content);
    }

    getAgentIcon(type) {
        const icons = {
            'analyzer': '🔍',
            'responder': '📋',
            'mitigator': '🛡️',
            'reporter': '📊',
            'monitor': '👁️',
            'orchestrator': '🎯',
            'default': '🤖'
        };
        return icons[type.toLowerCase()] || icons['default'];
    }

    getAgentCapabilities(type) {
        const capabilities = {
            'analyzer': ['Threat pattern analysis', 'Signature matching', 'Confidence scoring', 'False positive detection'],
            'responder': ['Response planning', 'Action coordination', 'Priority assessment', 'Resource allocation'],
            'mitigator': ['IP blocking', 'Rate limiting', 'Connection dropping', 'Firewall rules'],
            'reporter': ['Alert generation', 'Incident reports', 'Stakeholder notifications', 'Compliance logging'],
            'monitor': ['Real-time surveillance', 'Pattern tracking', 'Anomaly detection', 'Health checks'],
            'orchestrator': ['Workflow coordination', 'Agent spawning', 'Policy enforcement', 'Status tracking']
        };
        return capabilities[type.toLowerCase()] || ['General processing', 'Task execution'];
    }

    loadThreats(threats) {
        // Filter to only show active (non-mitigated) threats
        const activeThreats = threats.filter(t =>
            t.status !== 'mitigated' && t.status !== 'false_positive'
        );

        this.data.threats = activeThreats;
        const tbody = document.getElementById('threatsTableBody');

        // Clear existing
        tbody.innerHTML = '';

        if (activeThreats.length === 0) {
            tbody.innerHTML = '<tr class="no-threats"><td colspan="6">No active threats</td></tr>';
            return;
        }

        activeThreats.forEach(threat => {
            const row = document.createElement('tr');
            row.dataset.threatId = threat.id;
            row.innerHTML = `
                <td>${threat.source_ip?.address || threat.source_ip || 'Unknown'}</td>
                <td>${threat.attack_signature?.attack_type || threat.attack_type || 'Unknown'}</td>
                <td><span class="severity ${threat.threat_level?.severity || threat.severity || 'medium'}">${threat.threat_level?.severity || threat.severity || 'Unknown'}</span></td>
                <td>${threat.status || 'detected'}</td>
                <td>${this.formatTime(threat.detected_at)}</td>
                <td>
                    <button class="btn" onclick="dashboard.mitigateThreat('${threat.id}')">Mitigate</button>
                    <button class="btn btn-danger" onclick="dashboard.dismissThreat('${threat.id}')">Dismiss</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    addAlert(alert) {
        // Store in data
        this.data.alerts.unshift(alert);
        if (this.data.alerts.length > 50) this.data.alerts.pop();

        const list = document.getElementById('alertsList');
        const noAlerts = list.querySelector('.no-alerts');
        if (noAlerts) noAlerts.remove();

        // Defensive coding for missing fields
        const title = alert.title || `${(alert.threat_type || 'Unknown').toUpperCase()} Alert`;
        const summary = alert.summary || `Threat detected from ${alert.source || 'unknown source'}`;
        const severity = alert.severity || 'medium';

        const item = document.createElement('div');
        item.className = `alert-item ${severity}`;
        item.innerHTML = `
            <div class="alert-content">
                <div class="alert-title">${title}</div>
                <div class="alert-summary">${summary}</div>
            </div>
            <div class="alert-time">${this.formatTime(alert.timestamp)}</div>
        `;

        list.insertBefore(item, list.firstChild);
        while (list.children.length > 20) list.removeChild(list.lastChild);
    }

    updateThreat(threat) {
        // Store in data
        const existingIdx = this.data.threats.findIndex(t => t.id === threat.id);
        if (existingIdx >= 0) {
            this.data.threats[existingIdx] = threat;
        } else {
            this.data.threats.unshift(threat);
        }

        const tbody = document.getElementById('threatsTableBody');
        const noThreats = tbody.querySelector('.no-threats');
        if (noThreats) noThreats.remove();

        let row = tbody.querySelector(`tr[data-threat-id="${threat.id}"]`);
        if (!row) {
            row = document.createElement('tr');
            row.dataset.threatId = threat.id;
            tbody.insertBefore(row, tbody.firstChild);
        }

        row.innerHTML = `
            <td>${threat.source_ip?.address || 'Unknown'}</td>
            <td>${threat.attack_signature?.attack_type || 'Unknown'}</td>
            <td><span class="severity ${threat.threat_level?.severity || 'medium'}">${threat.threat_level?.severity || 'Unknown'}</span></td>
            <td>${threat.status || 'Unknown'}</td>
            <td>${this.formatTime(threat.detected_at)}</td>
            <td>
                <button class="btn" onclick="dashboard.mitigateThreat('${threat.id}')">Mitigate</button>
                <button class="btn btn-danger" onclick="dashboard.dismissThreat('${threat.id}')">Dismiss</button>
            </td>
        `;
    }

    handleEvent(event) {
        console.log('Event received:', event);
    }

    handleThreatRemoved(threatId) {
        // Remove from local data
        this.data.threats = this.data.threats.filter(t => t.id !== threatId);

        // Remove row from DOM with animation
        const row = document.querySelector(`tr[data-threat-id="${threatId}"]`);
        if (row) {
            row.style.transition = 'all 0.3s ease';
            row.style.opacity = '0';
            row.style.transform = 'translateX(-20px)';
            setTimeout(() => {
                row.remove();
                // Show no threats message if empty
                const tbody = document.getElementById('threatsTableBody');
                if (tbody && tbody.children.length === 0) {
                    tbody.innerHTML = '<tr class="no-threats"><td colspan="6">No active threats</td></tr>';
                }
            }, 300);
        }

        // Update active threats counter in real-time
        const activeThreatsEl = document.getElementById('activeThreats');
        if (activeThreatsEl) {
            const currentCount = parseInt(activeThreatsEl.textContent) || 0;
            activeThreatsEl.textContent = Math.max(0, currentCount - 1);
        }

        // Increment threats mitigated counter
        const mitigatedEl = document.getElementById('threatsMitigated');
        if (mitigatedEl) {
            const currentCount = parseInt(mitigatedEl.textContent) || 0;
            mitigatedEl.textContent = currentCount + 1;
        }

        this.showNotification('Threat mitigated and removed from active monitoring', 'success');
    }

    // =============================================
    // ESCALATION HANDLING (Human-in-the-Loop)
    // =============================================

    addEscalatedThreat(escalation) {
        // Add to local data
        this.data.escalatedThreats = this.data.escalatedThreats || [];
        const exists = this.data.escalatedThreats.find(e => e.threat_id === escalation.threat_id);
        if (!exists) {
            this.data.escalatedThreats.push(escalation);
        }

        // Show escalation section
        const section = document.getElementById('escalationSection');
        if (section) {
            section.style.display = 'block';
        }

        // Update count badge
        const countEl = document.getElementById('escalationCount');
        if (countEl) {
            countEl.textContent = this.data.escalatedThreats.length;
        }

        // Render escalation queue
        this.renderEscalationQueue();

        // Show notification
        this.showNotification(
            `ESCALATION: ${escalation.severity.toUpperCase()} severity threat from ${escalation.source_ip} requires human review`,
            'warning'
        );
    }

    renderEscalationQueue() {
        const container = document.getElementById('escalationQueue');
        if (!container) return;

        if (!this.data.escalatedThreats?.length) {
            container.innerHTML = '<div class="no-escalations">No threats awaiting review</div>';
            const section = document.getElementById('escalationSection');
            if (section) section.style.display = 'none';
            return;
        }

        container.innerHTML = this.data.escalatedThreats.map(e => `
            <div class="escalation-card ${e.severity}">
                <div class="escalation-header">
                    <span class="severity-badge ${e.severity}">${e.severity.toUpperCase()}</span>
                    <span class="attack-type">${e.attack_type}</span>
                    <span class="escalation-time">${this.formatTime(e.escalated_at)}</span>
                </div>
                <div class="escalation-source">Source: ${e.source_ip}</div>
                <div class="escalation-summary">${e.summary}</div>
                <div class="escalation-confidence">Confidence: ${(e.confidence * 100).toFixed(0)}%</div>
                <div class="escalation-actions">
                    <button class="btn btn-approve" onclick="dashboard.approveEscalation('${e.threat_id}')">
                        Approve Mitigation
                    </button>
                    <button class="btn btn-dismiss" onclick="dashboard.dismissEscalation('${e.threat_id}')">
                        Dismiss (False Positive)
                    </button>
                </div>
            </div>
        `).join('');
    }

    async approveEscalation(threatId) {
        try {
            const response = await fetch(`/api/v1/threats/${threatId}/escalation/decide`, {
                method: 'POST',
                headers: {
                    'X-API-Key': this.apiKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: 'approve_mitigation' })
            });

            if (response.ok) {
                this.removeFromEscalationQueue(threatId);
                this.showNotification('Mitigation approved and executed', 'success');
            } else {
                const error = await response.json();
                this.showNotification(`Failed to approve: ${error.detail}`, 'error');
            }
        } catch (error) {
            console.error('Approval failed:', error);
            this.showNotification('Failed to approve mitigation', 'error');
        }
    }

    async dismissEscalation(threatId) {
        try {
            const response = await fetch(`/api/v1/threats/${threatId}/escalation/decide`, {
                method: 'POST',
                headers: {
                    'X-API-Key': this.apiKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    action: 'dismiss',
                    notes: 'Human dismissed as false positive'
                })
            });

            if (response.ok) {
                this.removeFromEscalationQueue(threatId);
                this.showNotification('Threat dismissed as false positive', 'success');
            } else {
                const error = await response.json();
                this.showNotification(`Failed to dismiss: ${error.detail}`, 'error');
            }
        } catch (error) {
            console.error('Dismissal failed:', error);
            this.showNotification('Failed to dismiss threat', 'error');
        }
    }

    removeFromEscalationQueue(threatId) {
        this.data.escalatedThreats = this.data.escalatedThreats.filter(e => e.threat_id !== threatId);

        // Update count
        const countEl = document.getElementById('escalationCount');
        if (countEl) {
            countEl.textContent = this.data.escalatedThreats.length;
        }

        // Re-render
        this.renderEscalationQueue();
    }

    // =============================================
    // MITIGATION MODAL WITH REAL-TIME AGENT SPAWNING
    // =============================================

    async mitigateThreat(threatId) {
        const threat = this.data.threats.find(t => t.id === threatId);
        if (!threat) {
            console.error('Threat not found:', threatId);
            return;
        }

        // Open mitigation modal
        this.openMitigationModal(threat);
    }

    openMitigationModal(threat) {
        const severity = threat.threat_level?.severity || threat.severity || 'medium';
        const attackType = threat.attack_signature?.attack_type || threat.attack_type || 'Unknown';
        const sourceIp = threat.source_ip?.address || threat.source_ip || 'Unknown';

        // Determine policy based on severity
        const policy = this.getMitigationPolicy(severity, attackType);

        const content = `
            <div class="mitigation-modal">
                <!-- Threat Information -->
                <div class="mitigation-threat-info">
                    <div class="threat-info-item">
                        <div class="label">Source IP</div>
                        <div class="value">${sourceIp}</div>
                    </div>
                    <div class="threat-info-item">
                        <div class="label">Attack Type</div>
                        <div class="value">${attackType}</div>
                    </div>
                    <div class="threat-info-item">
                        <div class="label">Severity</div>
                        <div class="value ${severity}">${severity.toUpperCase()}</div>
                    </div>
                    <div class="threat-info-item">
                        <div class="label">Threat ID</div>
                        <div class="value" style="font-size: 0.8rem; font-family: monospace;">${threat.id.substring(0, 12)}...</div>
                    </div>
                </div>

                <!-- Security Policy Panel -->
                <div class="policy-panel">
                    <div class="policy-header">
                        <span>🛡️</span>
                        <span>Active Security Policy: ${policy.name}</span>
                    </div>
                    <div class="policy-rules">
                        ${policy.rules.map(rule => `
                            <div class="policy-rule">
                                <span class="policy-rule-icon">✓</span>
                                <span>${rule}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- Agent Pipeline Visualization -->
                <div class="agent-pipeline-container">
                    <div class="pipeline-header">
                        <h4 style="margin: 0; color: var(--text-primary);">Agent Response Pipeline</h4>
                        <div class="pipeline-status" id="pipelineStatus">
                            <span class="dot"></span>
                            <span>Ready</span>
                        </div>
                    </div>
                    <div class="agent-pipeline" id="agentPipeline">
                        <div style="text-align: center; width: 100%; color: var(--text-secondary); padding: 2rem;">
                            Click "Execute Mitigation" to spawn response agents
                        </div>
                    </div>
                </div>

                <!-- Mitigation Log -->
                <div style="margin-top: 1rem;">
                    <h4 style="margin-bottom: 0.5rem; color: var(--text-primary);">Mitigation Log</h4>
                    <div class="mitigation-log" id="mitigationLog">
                        <div class="log-entry">
                            <span class="log-timestamp">${new Date().toLocaleTimeString()}</span>
                            <span class="log-agent">SYSTEM</span>
                            <span class="log-message">Mitigation workflow initialized</span>
                        </div>
                    </div>
                </div>

                <!-- Recommended Actions -->
                <div style="margin-top: 1.5rem;">
                    <h4 style="margin-bottom: 0.75rem; color: var(--text-primary);">Recommended Response Actions</h4>
                    <div class="mitigation-actions">
                        ${this.getMitigationActions(attackType, severity).map((action, idx) => `
                            <div class="mitigation-action-card ${idx === 0 ? 'recommended' : ''}"
                                 onclick="dashboard.selectMitigationAction('${action.id}', '${threat.id}')"
                                 id="action-${action.id}">
                                <div class="action-card-header">
                                    <span class="action-card-icon">${action.icon}</span>
                                    <span class="action-card-title">${action.name}</span>
                                </div>
                                <div class="action-card-description">${action.description}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- Footer Controls -->
                <div class="mitigation-footer" style="margin-top: 1.5rem; padding: 1rem 0; border-top: 1px solid var(--border-color);">
                    <button class="btn" onclick="dashboard.closeModal()" style="background: var(--bg-secondary);">Cancel</button>
                    <div>
                        <button class="btn btn-auto-mitigate" onclick="dashboard.autoMitigate('${threat.id}')"
                                style="margin-right: 0.5rem;">
                            Auto-Mitigate (AI)
                        </button>
                        <button class="btn btn-execute-mitigation" onclick="dashboard.executeMitigation('${threat.id}')">
                            Execute Mitigation
                        </button>
                    </div>
                </div>
            </div>
        `;

        this.openModal(`Threat Mitigation - ${attackType}`, content);
        this.selectedMitigationAction = this.getMitigationActions(attackType, severity)[0]?.id;
    }

    getMitigationPolicy(severity, attackType) {
        const policies = {
            critical: {
                name: 'DEFCON-1 Emergency Response',
                rules: [
                    'Immediate IP blocking without confirmation required',
                    'Automatic rate limiting at 0 requests/second',
                    'All mitigation agents spawn in parallel',
                    'Notify SOC team via all channels (Slack, PagerDuty, Email)',
                    'Enable enhanced logging and packet capture',
                    'Escalate to incident response team automatically'
                ]
            },
            high: {
                name: 'Active Defense Protocol',
                rules: [
                    'IP blocking after threat verification',
                    'Rate limiting at 10 requests/minute',
                    'Sequential agent spawning with verification',
                    'Alert SOC team via primary channel',
                    'Enable detailed logging for forensics',
                    'Monitor for attack pattern spread'
                ]
            },
            medium: {
                name: 'Standard Response Procedure',
                rules: [
                    'Rate limiting at 100 requests/minute',
                    'Monitor and log suspicious activity',
                    'Spawn analyzer agent for threat confirmation',
                    'Generate incident report',
                    'Queue for SOC review if patterns persist'
                ]
            },
            low: {
                name: 'Monitoring & Assessment',
                rules: [
                    'Log and monitor traffic patterns',
                    'No automatic blocking actions',
                    'Analyze for false positive indicators',
                    'Add to watchlist for 24-hour observation',
                    'Generate weekly summary report'
                ]
            }
        };

        return policies[severity] || policies.medium;
    }

    getMitigationActions(attackType, severity) {
        const baseActions = [
            {
                id: 'block_ip',
                name: 'Block Source IP',
                icon: '🚫',
                description: 'Immediately block the attacking IP address at the firewall level. Recommended for confirmed malicious sources.'
            },
            {
                id: 'rate_limit',
                name: 'Rate Limit',
                icon: '⏱️',
                description: 'Apply strict rate limiting to the source IP. Allows legitimate traffic while preventing abuse.'
            },
            {
                id: 'drop_connection',
                name: 'Drop Active Connections',
                icon: '✂️',
                description: 'Terminate all active connections from the source. Effective for ongoing attacks.'
            },
            {
                id: 'quarantine',
                name: 'Quarantine & Analyze',
                icon: '🔬',
                description: 'Redirect traffic to honeypot for analysis while protecting production systems.'
            }
        ];

        // Reorder based on attack type
        if (attackType.toLowerCase().includes('ddos') || attackType.toLowerCase().includes('flood')) {
            return [baseActions[0], baseActions[2], baseActions[1], baseActions[3]];
        } else if (attackType.toLowerCase().includes('scan')) {
            return [baseActions[1], baseActions[3], baseActions[0], baseActions[2]];
        } else if (attackType.toLowerCase().includes('brute')) {
            return [baseActions[0], baseActions[1], baseActions[2], baseActions[3]];
        }

        return baseActions;
    }

    selectMitigationAction(actionId, threatId) {
        // Update UI selection
        document.querySelectorAll('.mitigation-action-card').forEach(card => {
            card.style.borderColor = 'var(--border-color)';
            card.style.background = 'var(--bg-secondary)';
        });
        const selected = document.getElementById(`action-${actionId}`);
        if (selected) {
            selected.style.borderColor = 'var(--accent-blue)';
            selected.style.background = 'rgba(59, 130, 246, 0.15)';
        }
        this.selectedMitigationAction = actionId;
    }

    async executeMitigation(threatId) {
        const threat = this.data.threats.find(t => t.id === threatId);
        if (!threat) return;

        const action = this.selectedMitigationAction || 'block_ip';
        const pipelineEl = document.getElementById('agentPipeline');
        const logEl = document.getElementById('mitigationLog');
        const statusEl = document.getElementById('pipelineStatus');

        // Update status
        statusEl.innerHTML = '<span class="dot" style="background: var(--accent-blue);"></span><span>Executing...</span>';
        statusEl.classList.add('executing');

        // Clear pipeline
        pipelineEl.innerHTML = '';

        // Spawn agents dynamically
        await this.spawnMitigationAgents(threatId, action, pipelineEl, logEl);
    }

    async spawnMitigationAgents(threatId, action, pipelineEl, logEl) {
        const threat = this.data.threats.find(t => t.id === threatId);
        const severity = threat?.threat_level?.severity || threat?.severity || 'medium';

        // Define agent spawn sequence based on severity
        const agentSequence = this.getAgentSequence(severity, action);

        for (let i = 0; i < agentSequence.length; i++) {
            const agent = agentSequence[i];

            // Spawn agent node
            await this.spawnAgentNode(agent, pipelineEl, logEl, i);

            // Execute agent action
            await this.executeAgentAction(agent, threatId, logEl);

            // Mark agent as completed
            this.completeAgentNode(agent.id);
        }

        // Complete mitigation
        this.addLogEntry(logEl, 'ORCHESTRATOR', 'Mitigation workflow completed successfully', 'success');

        const statusEl = document.getElementById('pipelineStatus');
        statusEl.innerHTML = '<span class="dot" style="background: var(--accent-green);"></span><span>Completed</span>';

        // Call API to execute actual mitigation
        try {
            const response = await fetch(`/api/v1/threats/${threatId}/mitigate`, {
                method: 'POST',
                headers: {
                    'X-API-Key': this.apiKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: action })
            });
            const result = await response.json();

            if (result.success) {
                this.addLogEntry(logEl, 'API', `Threat ${threatId.substring(0, 8)} mitigated via ${action}`, 'success');

                // Remove from threats table
                setTimeout(() => {
                    this.removeThreatFromTable(threatId);
                    this.closeModal();
                }, 2000);
            }
        } catch (error) {
            this.addLogEntry(logEl, 'API', `Mitigation API call failed: ${error.message}`, 'error');
        }
    }

    getAgentSequence(severity, action) {
        const baseSequence = [
            { id: 'orchestrator', name: 'Mitigation Orchestrator', icon: '🎯', actions: ['Coordinating response', 'Spawning agents'] },
            { id: 'analyzer', name: 'Threat Analyzer', icon: '🔍', actions: ['Analyzing threat vectors', 'Confirming attack signature'] },
            { id: 'responder', name: 'Response Planner', icon: '📋', actions: ['Generating response plan', 'Validating actions'] },
            { id: 'mitigator', name: 'Mitigator Agent', icon: '🛡️', actions: [`Executing ${action}`, 'Verifying mitigation'] },
            { id: 'reporter', name: 'Reporter Agent', icon: '📊', actions: ['Generating incident report', 'Notifying stakeholders'] }
        ];

        // Add more agents for critical threats
        if (severity === 'critical') {
            baseSequence.splice(2, 0,
                { id: 'forensics', name: 'Forensics Collector', icon: '🔬', actions: ['Capturing evidence', 'Preserving logs'] }
            );
            baseSequence.push(
                { id: 'escalation', name: 'Escalation Agent', icon: '🚨', actions: ['Alerting SOC team', 'Creating incident ticket'] }
            );
        }

        return baseSequence;
    }

    async spawnAgentNode(agent, pipelineEl, logEl, index) {
        return new Promise(resolve => {
            setTimeout(() => {
                const node = document.createElement('div');
                node.className = 'agent-node spawning';
                node.id = `agent-node-${agent.id}`;
                node.innerHTML = `
                    <div class="agent-node-header">
                        <div class="agent-node-icon">${agent.icon}</div>
                        <div class="agent-node-name">${agent.name}</div>
                    </div>
                    <div class="agent-node-status">Initializing...</div>
                    <div class="agent-node-actions" id="agent-actions-${agent.id}"></div>
                    <div class="agent-node-progress">
                        <div class="bar" style="width: 0%"></div>
                    </div>
                `;
                pipelineEl.appendChild(node);

                this.addLogEntry(logEl, 'SPAWNER', `Agent spawned: ${agent.name}`);

                // Animation
                setTimeout(() => {
                    node.classList.remove('spawning');
                    node.classList.add('active');
                    resolve();
                }, 300);
            }, index * 400);
        });
    }

    async executeAgentAction(agent, threatId, logEl) {
        const node = document.getElementById(`agent-node-${agent.id}`);
        const actionsEl = document.getElementById(`agent-actions-${agent.id}`);
        const statusEl = node.querySelector('.agent-node-status');
        const progressBar = node.querySelector('.agent-node-progress .bar');

        node.classList.remove('active');
        node.classList.add('executing');
        statusEl.textContent = 'Executing...';

        for (let i = 0; i < agent.actions.length; i++) {
            const action = agent.actions[i];

            // Add action to node
            const actionEl = document.createElement('div');
            actionEl.textContent = `→ ${action}`;
            actionEl.style.opacity = '0.5';
            actionsEl.appendChild(actionEl);

            // Update progress
            progressBar.style.width = `${((i + 1) / agent.actions.length) * 100}%`;

            // Log
            this.addLogEntry(logEl, agent.name.toUpperCase().replace(' ', '_'), action);

            // Simulate processing time
            await new Promise(r => setTimeout(r, 500 + Math.random() * 500));

            actionEl.style.opacity = '1';
            actionEl.style.color = 'var(--accent-green)';
        }

        statusEl.textContent = 'Completed';
    }

    completeAgentNode(agentId) {
        const node = document.getElementById(`agent-node-${agentId}`);
        if (node) {
            node.classList.remove('executing');
            node.classList.add('completed');
        }
    }

    addLogEntry(logEl, agent, message, type = '') {
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = `
            <span class="log-timestamp">${new Date().toLocaleTimeString()}</span>
            <span class="log-agent">${agent}</span>
            <span class="log-message ${type}">${message}</span>
        `;
        logEl.appendChild(entry);
        logEl.scrollTop = logEl.scrollHeight;
    }

    async autoMitigate(threatId) {
        const threat = this.data.threats.find(t => t.id === threatId);
        if (!threat) return;

        const severity = threat.threat_level?.severity || threat.severity || 'medium';

        // Auto-select best action based on AI analysis
        const bestAction = severity === 'critical' || severity === 'high' ? 'block_ip' : 'rate_limit';
        this.selectedMitigationAction = bestAction;

        const logEl = document.getElementById('mitigationLog');
        this.addLogEntry(logEl, 'AI_ENGINE', `Auto-selecting mitigation: ${bestAction} based on ${severity} severity`);

        await this.executeMitigation(threatId);
    }

    removeThreatFromTable(threatId) {
        // Remove from data
        this.data.threats = this.data.threats.filter(t => t.id !== threatId);

        // Remove from DOM
        const row = document.querySelector(`tr[data-threat-id="${threatId}"]`);
        if (row) {
            row.style.transition = 'all 0.3s ease';
            row.style.opacity = '0';
            row.style.transform = 'translateX(20px)';
            setTimeout(() => row.remove(), 300);
        }

        // Update metrics
        const activeThreatsEl = document.getElementById('activeThreats');
        if (activeThreatsEl) {
            activeThreatsEl.textContent = this.data.threats.length;
        }
    }

    // =============================================
    // DISMISS FUNCTIONALITY
    // =============================================

    async dismissThreat(threatId) {
        // Show confirmation modal
        const threat = this.data.threats.find(t => t.id === threatId);
        if (!threat) return;

        const attackType = threat.attack_signature?.attack_type || threat.attack_type || 'Unknown';
        const sourceIp = threat.source_ip?.address || threat.source_ip || 'Unknown';

        const content = `
            <div style="text-align: center; padding: 1rem;">
                <div style="font-size: 3rem; margin-bottom: 1rem;">⚠️</div>
                <h3 style="margin-bottom: 1rem; color: var(--accent-yellow);">Dismiss Threat?</h3>
                <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                    You are about to dismiss the <strong>${attackType}</strong> threat from <strong>${sourceIp}</strong>.
                    This action will permanently remove the threat from monitoring.
                </p>

                <div style="margin-bottom: 1.5rem;">
                    <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary); text-align: left;">
                        Dismissal Reason (required):
                    </label>
                    <select id="dismissReason" style="width: 100%; padding: 0.75rem; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0.375rem; color: var(--text-primary);">
                        <option value="">Select a reason...</option>
                        <option value="false_positive">False Positive - Legitimate Traffic</option>
                        <option value="known_scanner">Known Security Scanner (Authorized)</option>
                        <option value="internal_testing">Internal Penetration Testing</option>
                        <option value="resolved_externally">Resolved via External Means</option>
                        <option value="low_priority">Low Priority - Will Monitor</option>
                        <option value="duplicate">Duplicate Entry</option>
                        <option value="other">Other (Specify in Notes)</option>
                    </select>
                </div>

                <div style="margin-bottom: 1.5rem;">
                    <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary); text-align: left;">
                        Additional Notes:
                    </label>
                    <textarea id="dismissNotes" placeholder="Optional: Add any additional context..."
                        style="width: 100%; padding: 0.75rem; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0.375rem; color: var(--text-primary); min-height: 80px; resize: vertical;"></textarea>
                </div>

                <div style="display: flex; gap: 1rem; justify-content: center;">
                    <button class="btn" onclick="dashboard.closeModal()" style="background: var(--bg-secondary);">Cancel</button>
                    <button class="btn btn-danger" onclick="dashboard.confirmDismiss('${threatId}')">Confirm Dismiss</button>
                </div>
            </div>
        `;

        this.openModal('Dismiss Threat', content);
    }

    async confirmDismiss(threatId) {
        const reason = document.getElementById('dismissReason')?.value;
        const notes = document.getElementById('dismissNotes')?.value || '';

        if (!reason) {
            alert('Please select a dismissal reason');
            return;
        }

        try {
            const response = await fetch(`/api/v1/threats/${threatId}`, {
                method: 'DELETE',
                headers: {
                    'X-API-Key': this.apiKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ reason, notes })
            });

            if (response.ok) {
                this.removeThreatFromTable(threatId);
                this.closeModal();

                // Show success notification
                this.showNotification('Threat dismissed successfully', 'success');
            } else {
                const error = await response.json();
                this.showNotification(`Failed to dismiss: ${error.detail}`, 'error');
            }
        } catch (error) {
            console.error('Dismissal failed:', error);
            this.showNotification('Failed to dismiss threat', 'error');
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            background: ${type === 'success' ? 'var(--accent-green)' : type === 'error' ? 'var(--accent-red)' : 'var(--accent-blue)'};
            color: white;
            border-radius: 0.5rem;
            z-index: 10000;
            animation: slideIn 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        `;
        notification.textContent = message;
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(20px)';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    formatTime(timestamp) {
        if (!timestamp) return '--';
        return new Date(timestamp).toLocaleTimeString();
    }

    formatComponentName(name) {
        return name.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
    }

    formatAgentName(type) {
        return type.charAt(0).toUpperCase() + type.slice(1) + ' Agent';
    }

    formatAgentStats(stats) {
        if (!stats) return '';
        return Object.entries(stats).slice(0, 3).map(([key, value]) => `${key}: ${value}`).join(' | ');
    }

    startClock() {
        const updateClock = () => {
            document.getElementById('systemTime').textContent = new Date().toLocaleString();
        };
        updateClock();
        setInterval(updateClock, 1000);
    }

    setupEventListeners() {
        setInterval(() => {
            if (this.isConnected && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ type: 'ping' }));
            }
        }, 30000);
    }

    // Toggle threats section expand/collapse (legacy - now uses toggleSection)
    toggleThreatsSection() {
        this.toggleSection('threatsSection');
    }
}

// Initialize dashboard
const dashboard = new CyberShieldDashboard();
