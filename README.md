# PacketPeeper - Network Packet Sniffer

PacketPeeper is a modern network packet sniffer and analyzer that provides real-time monitoring of network traffic with a beautiful web interface. It captures and displays detailed information about network packets, allowing users to analyze network behavior and troubleshoot connectivity issues.

![PacketPeeper Dashboard](https://via.placeholder.com/800x400?text=PacketPeeper+Dashboard)

## Features

- **Real-time Packet Capture**: Monitor network traffic in real-time with detailed packet information
- **Protocol Analysis**: Automatically categorize packets by protocol (TCP, UDP, ICMP, HTTP, HTTPS, DNS)
- **Traffic Statistics**: View statistics about different types of network traffic
- **Detailed Packet Information**: Examine detailed information about each captured packet
- **Modern Web Interface**: Clean, responsive UI built with React
- **WebSocket Communication**: Real-time updates using Socket.IO

## Project Structure

```
NetworkSniffer/
├── app.py                  # Flask application and WebSocket server
├── packet_sniffer.py       # Core packet sniffing functionality
├── requirements.txt        # Python dependencies
├── my-app/                 # React frontend application
│   ├── public/             # Static files
│   ├── src/                # React source code
│   │   ├── components/     # React components
│   │   │   ├── PacketMonitor.js  # Main packet monitoring component
│   │   │   ├── PacketMonitor.css # Styling for packet monitor
│   │   │   ├── Navbar/     # Navigation component
│   │   │   └── Footer/     # Footer component
│   │   ├── App.js          # Main React application
│   │   ├── App.css         # Global styling
│   │   └── index.js        # React entry point
│   ├── package.json        # Node.js dependencies
│   └── .env                # Environment variables
└── templates/              # Flask templates
```

## Prerequisites

- Python 3.7+
- Node.js 14+
- Administrator/root privileges (required for packet capture)
- Network interface with packet capture capabilities

## Installation

### Backend Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/NetworkSniffer.git
   cd NetworkSniffer
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

### Frontend Setup

1. Navigate to the React app directory:
   ```
   cd my-app
   ```

2. Install Node.js dependencies:
   ```
   npm install
   ```

## Usage

### Starting the Backend

Run the Flask application with the network interface name as an argument:

```
python app.py Wi-Fi
```

Replace `Wi-Fi` with your network interface name. You can find your interface names by running:

```
python -c "from scapy.all import conf; print(conf.ifaces)"
```

### Starting the Frontend

In a separate terminal, navigate to the React app directory and start the development server:

```
cd my-app
npm start
```

The application will be available at http://localhost:3000.

## How It Works

1. The Python backend uses Scapy to capture network packets on the specified interface
2. Captured packets are processed and categorized by protocol
3. Packet information is sent to connected clients via WebSocket
4. The React frontend displays the packet information in real-time
5. Users can view detailed information about each packet and see traffic statistics

## Development

### Backend Development

The backend is built with Flask and uses Scapy for packet capture. The main components are:

- `app.py`: Flask application and WebSocket server
- `packet_sniffer.py`: Core packet sniffing functionality

### Frontend Development

The frontend is built with React and uses Socket.IO for real-time communication. The main components are:

- `PacketMonitor.js`: Main component for displaying packet information
- `App.js`: Main application component with layout and navigation

## Troubleshooting

- **Permission Issues**: Make sure you're running the application with administrator/root privileges
- **Interface Not Found**: Verify that you're using the correct network interface name
- **Connection Issues**: Ensure both the backend and frontend are running and the WebSocket connection is established

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Scapy](https://scapy.net/) - Network packet manipulation library
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [React](https://reactjs.org/) - JavaScript library for building user interfaces
- [Socket.IO](https://socket.io/) - Real-time bidirectional event-based communication 