import axios from "axios";
import { MOCK_PACKETS, MOCK_COUNTS, MOCK_TRAFFIC, MOCK_STATUS } from "./mockData";

const BASE_URL = process.env.REACT_APP_BASE_URL || 'http://3.99.207.184:5000';
// const BASE_URL = "http://localhost:5000";

const delay = (data, ms = 300) =>
  new Promise((resolve) => setTimeout(() => resolve(data), ms));

export const fetchPackets = async () => {
  try {
    const res = await axios.get(`${BASE_URL}/api/all_protocols`);
    return res.data;
  } catch (err) {
    console.warn("Using mock packets:", err.message);
    return delay(MOCK_PACKETS);
  }
};

export const fetchProtocolCounts = async () => {
  try {
    const res = await axios.get(`${BASE_URL}/api/summary`);
    return res.data;
  } catch (err) {
    console.warn("Using mock counts:", err.message);
    return delay(MOCK_COUNTS);
  }
};

export const fetchTraffic = async () => {
  try {
    const res = await axios.get(`${BASE_URL}/traffic`);
    return res.data;
  } catch (err) {
    console.warn("Using mock traffic:", err.message);
    return delay(MOCK_TRAFFIC);
  }
};

export const startSniffing = async () => {
  try {
    const res = await axios.post(`${BASE_URL}/api/start_sniffing`);
    return res.data;
  } catch (err) {
    console.error("Failed to start sniffing:", err.message);
    throw err;
  }
};

export const stopSniffing = async () => {
  try {
    const res = await axios.post(`${BASE_URL}/api/stop_sniffing`);
    return res.data;
  } catch (err) {
    console.error("Failed to stop sniffing:", err.message);
    throw err;
  }
};


export const fetchStatus = async () => {
  try {
    const res = await axios.get(`${BASE_URL}/api/status`);
    return res.data;
  } catch (err) {
    console.warn("Using mock status:", err.message);
    return delay(MOCK_STATUS);
  }
};

