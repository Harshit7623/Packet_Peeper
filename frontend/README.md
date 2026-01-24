# Packet Peeper Frontend

Modern React-based frontend for the Packet Peeper network security monitor.

## Tech Stack

- **React 19** with TypeScript
- **Vite** for fast development and building
- **Tailwind CSS v4** for styling
- **shadcn/ui** components (Radix UI primitives)
- **Zustand** for state management
- **Socket.IO** for real-time communication with backend
- **Recharts** for data visualization
- **Wouter** for routing
- **Framer Motion** for animations

## Quick Start

### Prerequisites
- Node.js 18+ 
- The Flask backend running on port 5000

### Installation

```bash
cd frontend
npm install
```

### Development

```bash
npm run dev
```

This will start the development server at `http://localhost:5173`.

### Build for Production

```bash
npm run build
```

Built files will be in the `dist/` directory.

## Configuration

Create a `.env` file (already included) with:

```env
VITE_BACKEND_URL=http://localhost:5000
```

## Project Structure

```
frontend/
├── src/
│   ├── components/
│   │   ├── layout/          # MainLayout, Sidebar, Header
│   │   └── ui/              # shadcn/ui components
│   ├── hooks/               # Custom React hooks
│   ├── lib/                 # Utilities and query client
│   ├── pages/               # Route pages
│   ├── services/            # Socket.IO service
│   ├── store/               # Zustand store
│   ├── App.tsx              # Main app component
│   ├── main.tsx             # Entry point
│   └── index.css            # Global styles
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
└── .env
```

## Pages

| Route | Component | Description |
|-------|-----------|-------------|
| `/` | Dashboard | Overview with stats and charts |
| `/packets` | PacketMonitor | Live packet capture view |
| `/alerts` | Alerts | Security alerts and events |
| `/network` | NetworkMap | Connected devices |
| `/traffic` | TrafficAnalysis | Traffic usage charts |
| `/analytics` | Analytics | Security insights |
| `/system` | SystemStats | System health metrics |
| `/logs` | Logs | Event history |
| `/settings` | Settings | Configuration |

## Backend Integration

The frontend connects to the Flask-SocketIO backend for real-time data:

- **WebSocket Events**: `new_packet`, `new_alert`, `devices_update`, `update_statistics`
- **REST API**: Available through the Vite proxy at `/api/*`

## Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run check` - Type check with TypeScript
