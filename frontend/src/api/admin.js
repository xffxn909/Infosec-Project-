import client from './client'

export const getUsers = () =>
  client.get('/admin/users')

export const createUser = (data) =>
  client.post('/admin/users', data)

export const updateUser = (id, data) =>
  client.put(`/admin/users/${id}`, data)

export const deleteUser = (id) =>
  client.delete(`/admin/users/${id}`)

export const getStats = () =>
  client.get('/admin/stats')
