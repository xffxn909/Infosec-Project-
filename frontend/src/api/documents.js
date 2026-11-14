import client from './client'

export const uploadDocument = (formData) =>
  client.post('/documents/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })

export const listDocuments = () =>
  client.get('/documents')

export const getDocument = (id) =>
  client.get(`/documents/${id}`)

export const downloadDocument = (id) =>
  client.get(`/documents/${id}/download`, { responseType: 'blob' })

export const signDocument = (id) =>
  client.post(`/documents/${id}/sign`)

export const verifyDocument = (id) =>
  client.post(`/documents/${id}/verify`)

export const deleteDocument = (id) =>
  client.delete(`/documents/${id}`)
