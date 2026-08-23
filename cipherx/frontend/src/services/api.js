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

export const checkHealth = async () => {
  const response = await apiClient.get('/health');
  return response.data;
};
