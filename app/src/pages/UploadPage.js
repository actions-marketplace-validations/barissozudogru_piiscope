import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Button, TextField, Typography, Paper, MenuItem, Select, InputLabel, FormControl } from '@mui/material';
import { useAuth } from '../App';
import * as api from '../api';

export default function UploadPage() {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [profiles, setProfiles] = useState([]);
  const [selectedProfile, setSelectedProfile] = useState('');
  const [file, setFile] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadProfiles() {
      try {
        const data = await api.getProfiles(token);
        setProfiles(data);
      } catch (err) {
        setError('Failed to load profiles');
      }
    }
    loadProfiles();
  }, [token]);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file || !selectedProfile) {
      setError('Please select a file and profile');
      return;
    }
    try {
      const job = await api.uploadFile(selectedProfile, file, token);
      navigate(`/jobs/${job.id}`);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
      <Paper elevation={3} sx={{ padding: 4, maxWidth: 500, width: '100%' }}>
        <Typography variant="h5" gutterBottom>Upload Dataset</Typography>
        <form onSubmit={handleUpload}>
          <FormControl fullWidth margin="normal">
            <InputLabel id="profile-label">Profile</InputLabel>
            <Select
              labelId="profile-label"
              value={selectedProfile}
              label="Profile"
              onChange={(e) => setSelectedProfile(e.target.value)}
            >
              {profiles.map((p) => (
                <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <Button variant="outlined" component="label" fullWidth sx={{ mt: 2 }}>
            Choose File
            <input
              type="file"
              accept=".csv,.json,.parquet"
              hidden
              onChange={(e) => setFile(e.target.files[0])}
            />
          </Button>
          {file && <Typography variant="body2" sx={{ mt: 1 }}>Selected: {file.name}</Typography>}
          {error && <Typography color="error">{error}</Typography>}
          <Button type="submit" variant="contained" fullWidth sx={{ mt: 3 }}>Start Scan</Button>
        </form>
      </Paper>
    </Box>
  );
}