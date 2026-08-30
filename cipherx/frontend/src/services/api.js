import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const analyzeUrl = async (url) => {
  try {
    const response = await apiClient.post('/analyze', { url });
    return response.data;
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(error.response.data.detail || 'Analysis failed on backend.');
    }
    throw new Error('Network error. Backend might be unavailable.');
  }
};

export const advancedAnalyzeUrl = async (payload) => {
  try {
    const response = await apiClient.post('/advanced-analyze', payload);
    return response.data;
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(error.response.data.detail || 'Advanced analysis failed on backend.');
    }
    throw new Error('Network error. Backend might be unavailable.');
  }
};

export const fetchRecentScans = async (limit = 6) => {
  try {
    const response = await apiClient.get(`/recent?limit=${limit}`);
    return response.data;
  } catch (error) {
    console.error('Failed to fetch recent scans:', error);
    return [];
  }
};

export const fetchStats = async () => {
  try {
    const response = await apiClient.get('/stats');
    return response.data;
  } catch (error) {
    console.error('Failed to fetch stats:', error);
    return null;
  }
};

export const checkHealth = async () => {
  try {
    const response = await apiClient.get('/health');
    return response.data;
  } catch (error) {
    console.error('Health check failed:', error);
    return { status: 'error', service: 'CipherX API', database: 'unavailable' };
  }
};

export const signIn = async (email, password) => {
  try {
    const response = await apiClient.post('/auth/signin', { email, password });
    return response.data;
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(error.response.data.detail || 'Sign in failed.');
    }
    throw new Error('Network error. Unable to reach authentication service.');
  }
};

export const signUp = async (email, password, fullName) => {
  try {
    const response = await apiClient.post('/auth/signup', {
      email,
      password,
      full_name: fullName,
    });
    return response.data;
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(error.response.data.detail || 'Sign up failed.');
    }
    throw new Error('Network error. Unable to reach registration service.');
  }
};

export const signInWithGoogle = async ({ email, fullName, avatarUrl, googleId }) => {
  try {
    const response = await apiClient.post('/auth/google', {
      email,
      full_name: fullName,
      avatar_url: avatarUrl,
      google_id: googleId,
    });
    return response.data;
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(error.response.data.detail || 'Google sign in failed.');
    }
    throw new Error('Network error. Unable to complete Google authentication.');
  }
};

export const fetchUserQuota = async (userId) => {
  try {
    const response = await apiClient.get(`/user/quota?user_id=${encodeURIComponent(userId || 'guest_user')}`);
    return response.data;
  } catch (error) {
    console.error('Failed to fetch user quota:', error);
    return { used: 0, total: 3, remaining: 3 };
  }
};

