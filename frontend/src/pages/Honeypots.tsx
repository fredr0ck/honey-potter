import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../services/api'
import { useState } from 'react'
import './Honeypots.css'

export default function Honeypots() {
  const [showCreate, setShowCreate] = useState(false)
  const [newHoneypot, setNewHoneypot] = useState({
    name: '',
    description: '',
    type: 'http',
    port: 8080,
    address: '0.0.0.0',
  })
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [selectMode, setSelectMode] = useState(false)
  const queryClient = useQueryClient()

  const { data: honeypots, isLoading } = useQuery({
    queryKey: ['honeypots'],
    queryFn: () => api.get('/honeypots').then((res) => res.data),
  })

  const createMutation = useMutation({
    mutationFn: (data: any) => api.post('/honeypots', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['honeypots'] })
      setShowCreate(false)
      setNewHoneypot({
        name: '',
        description: '',
        type: 'http',
        port: 8080,
        address: '0.0.0.0',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/honeypots/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['honeypots'] })
      setSelectedIds(new Set())
    },
  })

  const bulkDeleteMutation = useMutation({
    mutationFn: (ids: string[]) => api.post('/honeypots/bulk-delete', ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['honeypots'] })
      setSelectedIds(new Set())
      setSelectMode(false)
    },
  })

  const startMutation = useMutation({
    mutationFn: (id: string) => api.post(`/honeypots/${id}/start`),
    onMutate: async (id: string) => {
      await queryClient.cancelQueries({ queryKey: ['honeypots'] })
      const previousHoneypots = queryClient.getQueryData(['honeypots'])
      queryClient.setQueryData(['honeypots'], (old: any) => {
        if (!Array.isArray(old)) return old
        return old.map((hp: any) =>
          hp.id === id ? { ...hp, status: 'running' } : hp
        )
      })
      return { previousHoneypots }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['honeypots'] })
    },
    onError: (error: any, id: string, context: any) => {
      if (context?.previousHoneypots) {
        queryClient.setQueryData(['honeypots'], context.previousHoneypots)
      }
      console.error('Failed to start honeypot:', error)
      const errorMessage = error.response?.data?.detail || error.message || 'Failed to start honeypot'
      alert(`Error: ${errorMessage}`)
      queryClient.invalidateQueries({ queryKey: ['honeypots'] })
    },
  })

  const stopMutation = useMutation({
    mutationFn: (id: string) => api.post(`/honeypots/${id}/stop`),
    onMutate: async (id: string) => {
      await queryClient.cancelQueries({ queryKey: ['honeypots'] })
      const previousHoneypots = queryClient.getQueryData(['honeypots'])
      queryClient.setQueryData(['honeypots'], (old: any) => {
        if (!Array.isArray(old)) return old
        return old.map((hp: any) =>
          hp.id === id ? { ...hp, status: 'stopped' } : hp
        )
      })
      return { previousHoneypots }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['honeypots'] })
    },
    onError: (error: any, id: string, context: any) => {
      if (context?.previousHoneypots) {
        queryClient.setQueryData(['honeypots'], context.previousHoneypots)
      }
      console.error('Failed to stop honeypot:', error)
      const errorMessage = error.response?.data?.detail || error.message || 'Failed to stop honeypot'
      alert(`Error: ${errorMessage}`)
      queryClient.invalidateQueries({ queryKey: ['honeypots'] })
    },
  })

  const handleCreate = () => {
    if (!newHoneypot.name.trim()) {
      alert('Please enter a name for the honeypot')
      return
    }
    createMutation.mutate({
      ...newHoneypot,
      config: {},
      notification_levels: { "1": false, "2": true, "3": true }
    })
  }

  const handleDelete = (id: string) => {
    if (window.confirm('Are you sure you want to delete this honeypot?')) {
      deleteMutation.mutate(id)
    }
  }

  const handleBulkDelete = () => {
    if (selectedIds.size === 0) {
      alert('Please select at least one honeypot to delete.')
      return
    }
    if (window.confirm(`Are you sure you want to delete ${selectedIds.size} selected honeypot(s)?`)) {
      bulkDeleteMutation.mutate(Array.from(selectedIds))
    }
  }

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const newSet = new Set(prev)
      if (newSet.has(id)) {
        newSet.delete(id)
      } else {
        newSet.add(id)
      }
      return newSet
    })
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === (honeypots?.length || 0)) {
      setSelectedIds(new Set())
    } else {
      const allIds = new Set(honeypots?.map((hp: any) => hp.id) || [])
      setSelectedIds(allIds)
    }
  }

  return (
    <div className="honeypots">
      <div className="header">
        <h1>Honeypots</h1>
        <div className="actions">
          <button onClick={() => setShowCreate(!showCreate)} className="create-toggle-btn">
            {showCreate ? 'Hide Create Form' : '+ Create'}
          </button>
          <button onClick={() => setSelectMode(!selectMode)} className="select-mode-toggle-btn">
            {selectMode ? 'Exit Select Mode' : 'Select Mode'}
          </button>
          {selectMode && (
            <button
              onClick={handleBulkDelete}
              className="bulk-delete-btn"
              disabled={selectedIds.size === 0}
            >
              Delete Selected ({selectedIds.size})
            </button>
          )}
        </div>
      </div>

      {showCreate && (
        <div className="create-form">
          <h3>Create Honeypot</h3>
          <div className="form-group">
            <label>
              Name (required):
              <input
                type="text"
                placeholder="Honeypot name"
                value={newHoneypot.name}
                onChange={(e) =>
                  setNewHoneypot({ ...newHoneypot, name: e.target.value })
                }
                required
              />
            </label>
          </div>
          <div className="form-group">
            <label>
              Description (optional):
              <input
                type="text"
                placeholder="Honeypot description"
                value={newHoneypot.description}
                onChange={(e) =>
                  setNewHoneypot({ ...newHoneypot, description: e.target.value })
                }
              />
            </label>
          </div>
          <div className="form-group">
            <label>
              Type:
              <select
                value={newHoneypot.type}
                onChange={(e) =>
                  setNewHoneypot({ ...newHoneypot, type: e.target.value })
                }
              >
                <option value="ssh">SSH</option>
                <option value="postgres">PostgreSQL</option>
                <option value="http">HTTP</option>
              </select>
            </label>
          </div>
          <div className="form-group">
            <label>
              Port:
              <input
                type="number"
                placeholder="Port"
                value={newHoneypot.port}
                onChange={(e) =>
                  setNewHoneypot({
                    ...newHoneypot,
                    port: parseInt(e.target.value) || 8080,
                  })
                }
                min="1"
                max="65535"
              />
            </label>
          </div>
          <div className="form-group">
            <label>
              Address:
              <input
                type="text"
                placeholder="Address"
                value={newHoneypot.address}
                onChange={(e) =>
                  setNewHoneypot({ ...newHoneypot, address: e.target.value })
                }
              />
            </label>
          </div>
          <button onClick={handleCreate} className="create-btn" disabled={createMutation.isPending}>
            {createMutation.isPending ? 'Creating...' : 'Create'}
          </button>
        </div>
      )}

      {isLoading ? (
        <p>Loading...</p>
      ) : (
        <div className="honeypots-list">
          {selectMode && (
            <div className="select-all-container">
              <label>
                <input
                  type="checkbox"
                  checked={selectedIds.size === (honeypots?.length || 0) && (honeypots?.length || 0) > 0}
                  onChange={toggleSelectAll}
                />
                Select All
              </label>
            </div>
          )}
          {Array.isArray(honeypots) && honeypots.length > 0 ? honeypots.map((hp: any) => (
            <div key={hp.id} className={`honeypot-card ${selectedIds.has(hp.id) ? 'selected' : ''}`}>
              {selectMode && (
                <input
                  type="checkbox"
                  className="select-checkbox"
                  checked={selectedIds.has(hp.id)}
                  onChange={() => toggleSelect(hp.id)}
                />
              )}
              <div className="honeypot-details">
                <div className="honeypot-info">
                  <h3>{hp.name || `${hp.type.toUpperCase()} Honeypot`}</h3>
                  <p>Type: {hp.type.toUpperCase()}</p>
                  <p>Port: {hp.port}</p>
                  <p>Address: {hp.address}</p>
                  <p className={`status-badge ${hp.status === 'running' ? 'status-running' : hp.status === 'error' ? 'status-error' : 'status-stopped'}`}>
                    Status: {hp.status}
                  </p>
                </div>
                {hp.description && (
                  <div className="honeypot-description">
                    <h4>Description</h4>
                    <p>{hp.description}</p>
                  </div>
                )}
              </div>
              {!selectMode && (
                <div className="honeypot-actions">
                  {hp.status === 'running' ? (
                    <button
                      onClick={() => stopMutation.mutate(hp.id)}
                      className="stop-btn"
                      disabled={stopMutation.isPending}
                    >
                      {stopMutation.isPending ? 'Stopping...' : 'Stop'}
                    </button>
                  ) : (
                    <button
                      onClick={() => startMutation.mutate(hp.id)}
                      className="start-btn"
                      disabled={startMutation.isPending}
                    >
                      {startMutation.isPending ? 'Starting...' : 'Start'}
                    </button>
                  )}
                  <button
                    onClick={() => handleDelete(hp.id)}
                    className="delete-btn"
                    title="Delete honeypot"
                  >
                    🗑️ Delete
                  </button>
                </div>
              )}
            </div>
          )) : <p>No honeypots yet. Create one to get started!</p>}
        </div>
      )}
    </div>
  )
}
