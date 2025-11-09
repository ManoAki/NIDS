from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from flask_migrate import Migrate
from datetime import datetime, timedelta
import os
import json
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids_events.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)

COLUMN_WIDTHS = {
    'timestamp': 19,    # YYYY-MM-DD HH:MM:SS
    'type': 25,        # Event type column
    'source_ip': 15,   # Source IP address
    'dest_ip': 15,     # Destination IP address
    'dest_port': 5,    # Port number
    'protocol': 6,     # Protocol name
    'severity': 8,     # Severity level
}

DETAIL_FORMAT = {
    'attack_info': 30,    # Attack details width
    'impact': 20,         # Impact assessment width  
    'recommendation': 40, # Recommendation width
}

POPUP_CONFIG = {
    'CHART_HEIGHT': 200,
    'MAX_RELATED': 5,
    'TIME_WINDOW': 24  # hours
}

ALERT_ANALYSIS = {
    'max_related': 5,
    'lookup_window': 24,  # hours
    'threat_levels': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
}

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    dest_ip = db.Column(db.String(50))  # Add destination IP
    dest_port = db.Column(db.Integer)    # Add destination port
    details = db.Column(db.Text)
    severity = db.Column(db.String(20))
    protocol = db.Column(db.String(10))  # Add protocol
    old_hash = db.Column(db.String(32))  # Add column for old hash
    new_hash = db.Column(db.String(32))  # Add column for new hash

    @property
    def formatted_event_data(self):
        """Format event data for consistent display with appropriate icons"""
        base_data = {
            'timestamp': self.timestamp.strftime('%H:%M:%S'),
            'type': self.event_type,
            'details': self.details,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'icon': self.get_event_icon()
        }

        if self.event_type == "File Modification":
            return {
                **base_data,
                'is_file_event': True,
                'alert_label': 'File Alert',
                'file_path': self.details.split(':')[0] if ':' in self.details else 'Unknown File',
                'old_hash': self.old_hash,
                'new_hash': self.new_hash,
                'icon': 'fa-file-alt'  # Override default icon for file events
            }
        
        return base_data

    def get_event_icon(self):
        """Get FontAwesome icon class based on event type"""
        icons = {
            'NMAP Scan': 'fa-search',
            'Port Scan': 'fa-network-wired',
            'DoS Attack': 'fa-shield-alt',
            'Brute Force': 'fa-key',
            'SQL Injection': 'fa-database',
            'XSS Attack': 'fa-code',
            'File Modification': 'fa-file-alt',
            'Authentication Failure': 'fa-user-lock',
            'Firewall Block': 'fa-ban',
            'Malware Detection': 'fa-bug',
            'Suspicious Traffic': 'fa-exclamation-triangle',
            'System Error': 'fa-exclamation-circle',
            'Configuration Change': 'fa-wrench',
            'Network Scan': 'fa-sitemap',
            'Data Exfiltration': 'fa-upload',
            'Privilege Escalation': 'fa-level-up-alt'
        }
        return icons.get(self.event_type, 'fa-shield-alt')  # Default icon if type not found

@app.route('/')
@app.route('/dashboard')
def dashboard():
    try:
        # Existing stats
        stats = {
            'total_attacks': SecurityEvent.query.count(),
            'recent_attacks': SecurityEvent.query.filter(
                SecurityEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).count(),
            'blocked_ips': len({event.source_ip for event in SecurityEvent.query.all() if event.source_ip}),
            'high_severity': SecurityEvent.query.filter_by(severity='HIGH').count(),
            
            # Add new statistical data
            'severity_distribution': {
                'high': SecurityEvent.query.filter_by(severity='HIGH').count(),
                'medium': SecurityEvent.query.filter_by(severity='MEDIUM').count(),
                'low': SecurityEvent.query.filter_by(severity='LOW').count()
            },
            
            # Add event type distribution
            'event_types': db.session.query(
                SecurityEvent.event_type,
                db.func.count(SecurityEvent.id).label('count')
            ).group_by(SecurityEvent.event_type).all(),
            
            # Add hourly attack distribution
            'hourly_attacks': db.session.query(
                db.func.strftime('%H', SecurityEvent.timestamp).label('hour'),
                db.func.count(SecurityEvent.id).label('count')
            ).group_by('hour').all(),
            
            # Add protocol distribution
            'protocols': db.session.query(
                SecurityEvent.protocol,
                db.func.count(SecurityEvent.id).label('count')
            ).filter(SecurityEvent.protocol.isnot(None))\
             .group_by(SecurityEvent.protocol).all(),
             
            # Add source IP analysis
            'top_attackers': db.session.query(
                SecurityEvent.source_ip,
                db.func.count(SecurityEvent.id).label('count')
            ).filter(SecurityEvent.source_ip.isnot(None))\
             .group_by(SecurityEvent.source_ip)\
             .order_by(db.func.count(SecurityEvent.id).desc())\
             .limit(5).all()
        }
        
        recent_events = SecurityEvent.query.order_by(
            SecurityEvent.timestamp.desc()
        ).limit(5).all()
        
        return render_template('dashboard.html', stats=stats, events=recent_events)
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        return render_template('error.html', message="Error loading dashboard data"), 500

@app.route('/events')
def events():
    try:
        # Add pagination to prevent memory overload
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        events_query = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc())
        paginated_events = events_query.paginate(page=page, per_page=per_page, error_out=False)
        
        if paginated_events is None:
            raise Exception("Failed to retrieve events data")
            
        all_events = paginated_events.items
        
        if not all_events and page == 1:
            # No events but not an error
            all_events = []
            
        return render_template('events.html', 
                             events=all_events,
                             pagination=paginated_events)
                             
    except Exception as e:
        app.logger.error(f"Events page error: {str(e)}")
        error_message = "Error loading events data. Please try again later."
        if app.debug:
            error_message += f" Debug info: {str(e)}"
        return render_template('error.html', message=error_message), 500

@app.route('/analysis')
def analysis():
    try:
        # Get attack statistics for analysis page
        attack_types = db.session.query(
            SecurityEvent.event_type, 
            db.func.count(SecurityEvent.id)
        ).filter(SecurityEvent.event_type.isnot(None))\
         .group_by(SecurityEvent.event_type).all()
        
        return render_template('analysis.html', attack_types=attack_types)
    except Exception as e:
        app.logger.error(f"Analysis page error: {str(e)}")
        return render_template('error.html', message="Error loading analysis data"), 500

@app.route('/api/events')
def get_events():
    try:
        events = SecurityEvent.query\
            .order_by(SecurityEvent.timestamp.desc())\
            .limit(100)\
            .all()
        
        return jsonify([
            event.formatted_event_data if hasattr(event, 'formatted_event_data') 
            else {
                'timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'type': event.event_type or 'Unknown',
                'source_ip': event.source_ip or 'Unknown',
                'dest_ip': event.dest_ip or 'Unknown',
                'dest_port': event.dest_port or 0,
                'protocol': event.protocol or 'Unknown',
                'details': event.details or '',
                'severity': event.severity or 'LOW',
                'is_file_event': False
            }
            for event in events
        ])
    except Exception as e:
        app.logger.error(f"Events API error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to fetch events'}), 500

@app.route('/api/stats')
def get_stats():
    try:
        # Add timezone handling for better date operations
        current_time = datetime.utcnow()
        
        # Get hourly statistics with proper error handling
        hourly_stats = db.session.query(
            db.func.strftime('%H', SecurityEvent.timestamp).label('hour'),
            db.func.count(SecurityEvent.id).label('count')
        ).group_by('hour').all()
        
        # Format hourly stats properly
        hourly_stats_dict = {str(h.hour).zfill(2): h.count for h in hourly_stats}
        
        # Get severity distribution with error handling
        severity_stats = db.session.query(
            SecurityEvent.severity.label('severity'),
            db.func.count(SecurityEvent.id).label('count')
        ).filter(SecurityEvent.severity.isnot(None))\
         .group_by('severity').all()
        
        # Format severity stats properly
        severity_stats_dict = {s.severity: s.count for s in severity_stats}
        
        # Get attack types with proper filtering
        attack_types = db.session.query(
            SecurityEvent.event_type.label('type'),
            db.func.count(SecurityEvent.id).label('count')
        ).filter(SecurityEvent.event_type.isnot(None))\
         .group_by('type').all()
        
        # Format attack types properly
        attack_types_dict = {a.type: a.count for a in attack_types}
        
        # Get recent trend with proper date handling
        seven_days_ago = current_time - timedelta(days=7)
        daily_trend = db.session.query(
            db.func.date(SecurityEvent.timestamp).label('date'),
            db.func.count(SecurityEvent.id).label('count')
        ).filter(SecurityEvent.timestamp >= seven_days_ago)\
         .group_by('date').all()
        
        # Format daily trend properly
        daily_trend_dict = {str(d.date): d.count for d in daily_trend}
        
        return jsonify({
            'hourly_stats': hourly_stats_dict,
            'severity_stats': severity_stats_dict,
            'attack_types': attack_types_dict,
            'daily_trend': daily_trend_dict
        })
    except Exception as e:
        app.logger.error(f"Stats API error: {str(e)}")
        db.session.rollback()  # Add session rollback on error
        return jsonify({'error': 'Failed to fetch statistics'}), 500

@app.route('/api/events/<time_range>')
def get_time_events(time_range):
    try:
        time_filters = {
            'hour': timedelta(hours=1),
            'day': timedelta(days=1),
            'week': timedelta(weeks=1)
        }
        
        if time_range not in time_filters:
            return jsonify({'error': 'Invalid time range'}), 400
            
        time_threshold = datetime.utcnow() - time_filters[time_range]
        events = SecurityEvent.query\
            .filter(SecurityEvent.timestamp >= time_threshold)\
            .order_by(SecurityEvent.timestamp.desc())\
            .all()

        formatted_events = []
        for e in events:
            # Format main event data
            event_data = {
                'timestamp': e.timestamp.strftime('%Y-%m-%d %H:%M:%S').ljust(COLUMN_WIDTHS['timestamp']),
                'type': (e.event_type or 'Unknown')[:COLUMN_WIDTHS['type']].ljust(COLUMN_WIDTHS['type']),
                'source_ip': (e.source_ip or 'Unknown')[:COLUMN_WIDTHS['source_ip']].center(COLUMN_WIDTHS['source_ip']),
                'dest_ip': (e.dest_ip or 'Unknown')[:COLUMN_WIDTHS['dest_ip']].center(COLUMN_WIDTHS['dest_ip']),
                'dest_port': str(e.dest_port or 0).rjust(COLUMN_WIDTHS['dest_port']),
                'protocol': (e.protocol or 'Unknown')[:COLUMN_WIDTHS['protocol']].center(COLUMN_WIDTHS['protocol']),
                'severity': (e.severity or 'LOW')[:COLUMN_WIDTHS['severity']].center(COLUMN_WIDTHS['severity']),
                'details': (e.details or '').strip(),
                
                # Add detailed popup information
                'extended_info': {
                    'event_id': e.id,
                    'full_timestamp': e.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                    'attack_details': {
                        'attack_type': e.event_type,
                        'source_analysis': analyze_source(e.source_ip),
                        'target_analysis': analyze_target(e.dest_ip, e.dest_port),
                        'detection_time': detect_time_window(e.timestamp),
                        'potential_impact': assess_impact(e)
                    },
                    'mitigations': get_mitigations(e.event_type, e.severity),
                    'related_events': get_related_events(e)
                }
            }
            
            # Clean up the data while maintaining alignment
            event_data = {k: v.rstrip() if isinstance(v, str) else v for k, v in event_data.items()}
            event_data['protocol'] = event_data['protocol'].upper()
            event_data['severity'] = event_data['severity'].upper()
            
            formatted_events.append(event_data)

        return jsonify(formatted_events)
                
    except Exception as e:
        app.logger.error(f"Events API error: {str(e)}")
        return jsonify({'error': 'Failed to fetch events'}), 500

@app.route('/api/alerts')
def get_alerts():
    try:
        # Get query parameters
        severity = request.args.get('severity')
        time_range = request.args.get('range', '24h')
        
        # Base query
        query = SecurityEvent.query
        
        # Apply filters
        if severity:
            query = query.filter(SecurityEvent.severity == severity.upper())
            
        # Apply time filter
        if time_range:
            time_filters = {
                '1h': timedelta(hours=1),
                '24h': timedelta(hours=24),
                '7d': timedelta(days=7),
                '30d': timedelta(days=30)
            }
            if time_range in time_filters:
                cutoff = datetime.utcnow() - time_filters[time_range]
                query = query.filter(SecurityEvent.timestamp >= cutoff)
        
        # Get results ordered by timestamp
        alerts = query.order_by(SecurityEvent.timestamp.desc()).all()
        
        return jsonify([{
            'id': alert.id,
            'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': alert.event_type,
            'source_ip': alert.source_ip,
            'dest_ip': alert.dest_ip,
            'dest_port': alert.dest_port,
            'protocol': alert.protocol,
            'severity': alert.severity,
            'details': alert.details,
            'metrics': get_event_metrics(alert),
            'impact': get_system_impact(alert),
            'threat_info': get_threat_analysis(alert.source_ip, alert.event_type)
        } for alert in alerts])
        
    except Exception as e:
        app.logger.error(f"Alerts API error: {str(e)}")
        return jsonify({'error': 'Failed to fetch alerts'}), 500

# Add new helper functions
def format_attack_details(event):
    """Format detailed attack information"""
    return {
        'attack_type': event.event_type,
        'attack_pattern': detect_attack_pattern(event),
        'source_info': get_source_details(event.source_ip),
        'target_info': get_target_details(event.dest_ip, event.dest_port)
    }

def get_impact_assessment(severity):
    """Generate impact assessment based on severity"""
    impacts = {
        'HIGH': 'Critical system impact - Immediate action required',
        'MEDIUM': 'Moderate impact - Investigation needed',
        'LOW': 'Minor impact - Monitor for escalation'
    }
    return impacts.get(severity, 'Unknown impact level')

def get_security_recommendations(event_type):
    """Get security recommendations based on event type"""
    recommendations = {
        'NMAP Scan': [
            'Block source IP at firewall',
            'Review firewall rules',
            'Enable port scan detection'
        ],
        'DoS Attack': [
            'Implement rate limiting',
            'Enable DDoS protection',
            'Contact upstream provider'
        ]
    }
    return recommendations.get(event_type, ['Monitor system logs', 'Review security policies'])

def get_related_events(event):
    """Find related security events"""
    related = SecurityEvent.query\
        .filter(SecurityEvent.source_ip == event.source_ip)\
        .filter(SecurityEvent.id != event.id)\
        .order_by(SecurityEvent.timestamp.desc())\
        .limit(5)\
        .all()
    
    return [{
        'timestamp': e.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'type': e.event_type,
        'severity': e.severity
    } for e in related]

def analyze_source(ip):
    """Analyze source IP for threat assessment"""
    try:
        return {
            'known_threat': is_known_threat(ip),
            'previous_attacks': get_previous_attacks(ip),
            'geolocation': get_ip_geolocation(ip),
            'reputation_score': calculate_threat_score(ip)
        }
    except Exception:
        return {}

def analyze_target(ip, port):
    """Analyze target for vulnerability assessment"""
    try:
        return {
            'service': identify_service(port),
            'criticality': assess_target_criticality(ip),
            'patch_status': check_patch_status(ip),
            'recent_activity': get_recent_target_activity(ip)
        }
    except Exception:
        return {}

def detect_time_window(timestamp):
    """Calculate detection time windows"""
    now = datetime.utcnow()
    delta = now - timestamp
    return {
        'detected_ago': str(delta),
        'time_window': calculate_attack_window(timestamp),
        'peak_time': identify_peak_attack_time(timestamp)
    }

def assess_impact(event):
    """Assess potential impact of security event"""
    return {
        'severity_level': event.severity,
        'affected_systems': identify_affected_systems(event),
        'data_risk': assess_data_risk(event),
        'service_impact': calculate_service_impact(event)
    }

def get_event_metrics(event):
    """Get key metrics for the event"""
    return {
        'detection_latency': calculate_detection_latency(event),
        'attack_duration': estimate_attack_duration(event),
        'affected_assets': count_affected_assets(event),
        'threat_level': assess_threat_level(event)
    }

def get_event_timeline(event):
    """Generate timeline of related events"""
    return {
        'first_seen': get_first_occurrence(event),
        'peak_activity': find_peak_activity(event),
        'related_events': get_chronological_events(event),
        'resolution_time': estimate_resolution_time(event)
    }

def calculate_risk_score(event):
    """Calculate normalized risk score 0-100"""
    base_score = SEVERITY_WEIGHTS.get(event.severity, 0)
    impact_mult = get_impact_multiplier(event)
    trend_adj = get_trend_adjustment(event)
    return min(100, base_score * impact_mult + trend_adj)

def get_threat_analysis(ip, event_type):
    """Get detailed threat analysis for IP and event type"""
    return {
        'threat_score': calculate_ip_threat_score(ip),
        'attack_pattern': identify_attack_pattern(ip),
        'historical_events': get_historical_events(ip),
        'attack_frequency': calculate_attack_frequency(ip),
        'geographic_info': get_geographic_info(ip)
    }

def get_system_impact(event):
    """Analyze system impact of security event"""
    return {
        'affected_services': identify_affected_services(event),
        'vulnerability_status': check_vulnerability_status(event),
        'risk_level': calculate_risk_level(event),
        'mitigation_priority': get_mitigation_priority(event)
    }

def get_detailed_event_metrics(event):
    """Get comprehensive event metrics"""
    return {
        'detection_time': format_detection_time(event.timestamp),
        'attack_duration': calculate_attack_duration(event),
        'related_incidents': find_related_incidents(event),
        'attack_vectors': identify_attack_vectors(event)
    }

def format_alert_details(event):
    """Format comprehensive alert details"""
    return {
        'alert_id': f"ALERT-{event.id:06d}",
        'timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'threat_analysis': get_threat_analysis(event.source_ip, event.event_type),
        'system_impact': get_system_impact(event),
        'event_metrics': get_detailed_event_metrics(event),
        'visualization_data': generate_visualization_data(event)
    }

# Remove the @app.before_first_request decorator and setup logging differently
def setup_logging():
    if not app.debug:
        # Set up file logging
        file_handler = logging.FileHandler('web_app.log')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Web app startup')

# Call setup_logging during app initialization
setup_logging()

@socketio.on('connect')
def handle_connect():
    emit_dashboard_metrics()

@socketio.on('request_dashboard_data')
def handle_dashboard_data():
    emit_dashboard_metrics()

def emit_dashboard_metrics():
    try:
        # Get real metrics from database
        total_alerts = SecurityEvent.query.count()
        critical_alerts = SecurityEvent.query.filter_by(severity='HIGH').count()
        active_threats = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        # Calculate system health based on various factors
        health_score = calculate_system_health()
        
        metrics = {
            'critical_alerts': critical_alerts,
            'total_alerts': total_alerts,
            'active_threats': active_threats,
            'max_threats': 100,  # Baseline max value
            'system_health': health_score,
            'top_threats': get_top_threats()
        }
        
        socketio.emit('dashboard_metrics', metrics)
    except Exception as e:
        app.logger.error(f"Error emitting metrics: {str(e)}")

def calculate_system_health():
    try:
        # Calculate health score based on various factors
        recent_alerts = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= datetime.utcnow() - timedelta(hours=1)
        ).count()
        
        high_severity = SecurityEvent.query.filter_by(severity='HIGH').count()
        total_events = SecurityEvent.query.count() or 1  # Prevent division by zero
        
        severity_ratio = (high_severity / total_events) * 100
        activity_score = min(100, max(0, 100 - (recent_alerts * 2)))
        
        health_score = 100 - (severity_ratio * 0.3 + (100 - activity_score) * 0.7)
        return round(max(0, min(100, health_score)))
    except Exception:
        return 100  # Default to 100 if calculation fails

def get_top_threats():
    try:
        top_source = SecurityEvent.query.with_entities(
            SecurityEvent.source_ip,
            db.func.count(SecurityEvent.id).label('count')
        ).group_by(SecurityEvent.source_ip).order_by(db.text('count DESC')).first()

        top_type = SecurityEvent.query.with_entities(
            SecurityEvent.event_type,
            db.func.count(SecurityEvent.id).label('count')
        ).group_by(SecurityEvent.event_type).order_by(db.text('count DESC')).first()

        return {
            'source': top_source[0] if top_source else 'None',
            'type': top_type[0] if top_type else 'None'
        }
    except Exception:
        return {'source': 'None', 'type': 'None'}

def broadcast_event(event_data):
    try:
        is_file_event = event_data.get('event_type') == 'File Modification'
        formatted_data = {
            'id': event_data.get('id', 0),
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': 'File Modification' if is_file_event else event_data.get('event_type'),
            'details': event_data.get('details', ''),
            'severity': event_data.get('severity', 'LOW'),
            'is_file_event': is_file_event,
            'alert_label': 'File Alert' if is_file_event else 'Security Alert',
            'file_path': event_data.get('details', '').split(':')[0] if is_file_event else None,
            'old_hash': event_data.get('old_hash'),
            'new_hash': event_data.get('new_hash'),
        }
        socketio.emit('new_security_event', formatted_data)
    except Exception as e:
        app.logger.error(f"Error broadcasting event: {str(e)}")

@socketio.on('request_alerts_history')
def handle_alerts_history_request(data):
    try:
        # Get last N alerts
        limit = data.get('limit', 50)
        alerts = SecurityEvent.query\
            .order_by(SecurityEvent.timestamp.desc())\
            .limit(limit)\
            .all()
            
        # Send alerts to client
        for alert in alerts:
            emit('alert_history', {
                'id': alert.id,
                'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'event_type': alert.event_type,
                'source_ip': alert.source_ip,
                'dest_ip': alert.dest_ip,
                'dest_port': alert.dest_port,
                'protocol': alert.protocol,
                'severity': alert.severity,
                'details': alert.details
            })
    except Exception as e:
        app.logger.error(f"Error sending alerts history: {str(e)}")
        emit('alert_error', {'message': 'Failed to fetch alerts history'})

if __name__ == '__main__':
    try:
        # Create base directories
        required_dirs = ['static', 'static/css', 'static/js', 'static/images', 'templates', 'instance']
        for directory in required_dirs:
            os.makedirs(directory, exist_ok=True)
            
        # Copy empty style.css if doesn't exist
        css_file = 'static/css/style.css'
        if not os.path.exists(css_file):
            with open(css_file, 'w') as f:
                f.write('/* Base styles will be added here */')
                
        # Create logo.svg if missing
        logo_path = 'static/images/logo.svg'
        if not os.path.exists(logo_path):
            with open(logo_path, 'w') as f:
                f.write('''<svg width="50" height="50" viewBox="0 0 50 50">
                    <circle cx="25" cy="25" r="20" fill="#0066cc"/>
                    <path d="M25 15v20M15 25h20" stroke="white" stroke-width="4"/>
                </svg>''')

        # Setup enhanced logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('web_app.log', mode='a'),
                logging.StreamHandler()
            ]
        )
        logger = logging.getLogger(__name__)
        logger.info("Starting application setup...")

        # Initialize database with app context
        with app.app_context():
            try:
                db.create_all()
                logger.info("Database tables created successfully")
                
                # Add test event if database is empty
                if not SecurityEvent.query.first():
                    test_event = SecurityEvent(
                        event_type="Test Event",
                        source_ip="127.0.0.1",
                        dest_ip="127.0.0.1",
                        dest_port=443,
                        protocol="TCP",
                        details="Initial test event",
                        severity="LOW"
                    )
                    db.session.add(test_event)
                    db.session.commit()
                    logger.info("Added test event to database")
                    
            except Exception as e:
                logger.error(f"Database initialization error: {e}")
                raise

        # Initialize Socket.IO
        socketio.init_app(app,
                         cors_allowed_origins="*",
                         async_mode='gevent',
                         logger=True,
                         engineio_logger=True)
        
        # Run the application
        logger.info("Starting web application on http://127.0.0.1:5000")
        socketio.run(app,
                    debug=True,
                    host='127.0.0.1',
                    port=5000,
                    use_reloader=True)

    except Exception as e:
        print(f"Startup Error: {e}")
        logging.error(f"Application startup failed: {e}")
        raise
