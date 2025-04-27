from flask import Flask
from flask_socketio import SocketIO, emit
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connection_status', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('test')
def handle_test():
    print('Test event received')
    emit('test_response', {'message': 'Test successful'})

if __name__ == '__main__':
    print('Starting test server on http://localhost:5001')
    socketio.run(app, debug=True, host='0.0.0.0', port=5001) 