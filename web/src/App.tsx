import { HashRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Shell } from './components/Shell'
import { LiveProvider } from './lib/live'
import { AlertsPage } from './pages/Alerts'
import { AnalyticsPage } from './pages/Analytics'
import { AnomaliesPage } from './pages/Anomalies'
import { BaselinePage } from './pages/Baseline'
import { DashboardPage } from './pages/Dashboard'
import { DeviceDetailPage } from './pages/DeviceDetail'
import { AssetsPage } from './pages/Assets'
import { DevicesPage } from './pages/Devices'
import { PolicyPage } from './pages/Policy'
import { RawPage } from './pages/Raw'

export default function App() {
  return (
    <LiveProvider>
      <HashRouter>
        <Routes>
          <Route element={<Shell />}>
            <Route index element={<DashboardPage />} />
            <Route path="analytics" element={<AnalyticsPage />} />
            <Route path="devices" element={<DevicesPage />} />
            <Route path="assets" element={<AssetsPage />} />
            <Route path="device/:mac" element={<DeviceDetailPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="anomalies" element={<AnomaliesPage />} />
            <Route path="policy" element={<PolicyPage />} />
            <Route path="baseline" element={<BaselinePage />} />
            <Route path="raw/:endpoint?" element={<RawPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </HashRouter>
    </LiveProvider>
  )
}
