# app.py
from flask import Flask, render_template
from flask_socketio import SocketIO
from classes.FlowClassifier import FlowClassifier

app = Flask(__name__, template_folder='templates/')
app.config['SECRET_KEY'] = 'secret'

# Initialize SocketIO with async_mode for background thread support
socketio = SocketIO(app, async_mode='threading', logger=True, engineio_logger=True, cors_allowed_origins="*")

model_path = '../../models/CIC_IDS_2017/xgb_clf_multiclass.pkl'
classifier = FlowClassifier(model_path=model_path, socketio=socketio)

@app.route('/')
def index(c=classifier.start_capture()):
    """Serve the dashboard interface"""
    return c


@socketio.on('connection', namespace='/flows')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    socketio.emit('status', {'message': 'Connected to flow monitor'},
                  namespace='/flows')
    socketio.start_background_task(target=classifier.start_capture)

socketio.run(app, host='0.0.0.0', port=5000, debug=True)