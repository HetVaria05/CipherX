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
  const response = await apiClient.get('/health');
  return response.data;
};
