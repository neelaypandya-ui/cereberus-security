import { Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

function App() {
  const token = localStorage.getItem('cereberus_token');

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/dashboard"
        element={token ? <Dashboard /> : <Navigate to="/login" />}
      />
      <Route path="*" element={<Navigate to={token ? '/dashboard' : '/login'} />} />
    </Routes>
  );
}

export default App;
