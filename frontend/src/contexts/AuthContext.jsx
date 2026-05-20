import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import api from '../api';

const AuthContext = createContext(null);
const VALID_ROLES = ['admin', 'analyst'];
const INACTIVITY_MS = 30 * 60 * 1000; // 30 minutes

export function AuthProvider({ children }) {
  const [user, setUser]   = useState(null);
  const [ready, setReady] = useState(false); // false until token verified with backend

  // On mount: verify stored token with backend before allowing access
  useEffect(() => {
    const verify = async () => {
      const stored = api.user();
      if (!stored || !VALID_ROLES.includes(stored.role)) {
        api.clear();
        setReady(true);
        return;
      }
      try {
        const me = await api.me();
        if (me && VALID_ROLES.includes(me.role)) {
          api.setSession(null, me);
          setUser(me);
        } else {
          api.clear();
        }
      } catch {
        api.clear();
      } finally {
        setReady(true);
      }
    };
    verify();
  }, []);

  // Inactivity timeout — log out after 30 min with no interaction
  useEffect(() => {
    if (!user) return;
    let timer;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        api.clear();
        setUser(null);
        window.location.href = '/login';
      }, INACTIVITY_MS);
    };
    const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];
    events.forEach(e => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => {
      clearTimeout(timer);
      events.forEach(e => window.removeEventListener(e, reset));
    };
  }, [user]);

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
    <AuthContext.Provider value={{ user, ready, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
