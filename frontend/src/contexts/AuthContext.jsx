import React, { createContext, useContext, useState, useCallback } from 'react';
import api from '../api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => api.user());

  const login = useCallback(async (email, password) => {
    const me = await api.login(email, password);
    setUser(me);
    return me;
  }, []);

  const logout = useCallback(() => {
    api.clear();
    setUser(null);
    window.location.href = '/login';
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      const me = await api.me();
      api.setSession(null, me);
      setUser(me);
      return me;
    } catch {
      return user;
    }
  }, [user]);

  return (
    <AuthContext.Provider value={{ user, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
