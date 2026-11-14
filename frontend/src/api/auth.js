import client from './client'

export const login = (email, password) =>
  client.post('/auth/login', { email, password })

export const register = (userData) =>
  client.post('/auth/register', userData)

export const getMe = () =>
  client.get('/auth/me')

export const setupMFA = () =>
  client.post('/auth/mfa/setup')

export const verifyMFA = (code) =>
  client.post('/auth/mfa/verify', { code })

export const logout = () =>
  client.post('/auth/logout')
