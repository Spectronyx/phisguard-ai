import { BrowserRouter, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import EmailScanner from "./pages/EmailScanner";
import UrlScanner from "./pages/UrlScanner";
import History from "./pages/History";
import ScanDetail from "./pages/ScanDetail";
import About from "./pages/About";
import NotFound from "./pages/NotFound";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="email" element={<EmailScanner />} />
          <Route path="url" element={<UrlScanner />} />
          <Route path="history" element={<History />} />
          <Route path="history/:id" element={<ScanDetail />} />
          <Route path="about" element={<About />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
