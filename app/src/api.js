// API helper functions for interacting with the backend

const BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

async function request(url, options = {}) {
  const res = await fetch(BASE_URL + url, options);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json();
}

export async function login(username, password) {
  const body = new URLSearchParams();
  body.append('username', username);
  body.append('password', password);
  const res = await fetch(BASE_URL + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error('Login failed');
  }
  return res.json();
}

export async function getProfiles(token) {
  return request('/profiles/', {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function uploadFile(profileId, file, token) {
  const formData = new FormData();
  formData.append('file', file);
  // query parameter for profileId
  const url = `/scan/upload?profile_id=${profileId}`;
  const res = await fetch(BASE_URL + url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || 'Upload failed');
  }
  return res.json();
}

export async function getJob(jobId, token) {
  return request(`/scan/jobs/${jobId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function getFindings(jobId, token) {
  return request(`/scan/jobs/${jobId}/findings?limit=1000`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function getMetrics(jobId, token) {
  return request(`/scan/jobs/${jobId}/metrics`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function exportJob(jobId, token) {
  return request(`/scan/jobs/${jobId}/export`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function getJobs(token) {
  return request('/scan/jobs', {
    headers: { Authorization: `Bearer ${token}` },
  });
}