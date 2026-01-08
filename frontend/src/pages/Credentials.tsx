import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../services/api'
import { useState } from 'react'
import './Credentials.css'

export default function Credentials() {
  const [showGenerate, setShowGenerate] = useState(false)
  const [generateMode, setGenerateMode] = useState<'auto' | 'manual'>('auto')
  const [generateForm, setGenerateForm] = useState({
    service_type: 'ssh',
    count: 1,
  })
  const [manualTokens, setManualTokens] = useState<Array<{ username: string; meta_data: string }>>([
    { username: '', meta_data: '' }
  ])
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [selectMode, setSelectMode] = useState(false)
  const queryClient = useQueryClient()

  const { data: credentials, isLoading } = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.get('/credentials').then((res) => res.data),
  })

  const generateMutation = useMutation({
    mutationFn: (data: any) => api.post('/credentials/generate', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
      setShowGenerate(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/credentials/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
      setSelectedIds(new Set())
    },
  })

  const bulkDeleteMutation = useMutation({
    mutationFn: (ids: string[]) => api.post('/credentials/bulk-delete', ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
      setSelectedIds(new Set())
      setSelectMode(false)
    },
  })

  const handleGenerate = () => {
    if (generateMode === 'manual') {
      const validTokens = manualTokens.filter(t => t.username.trim() !== '')
      if (validTokens.length === 0) {
        alert('Please add at least one token with username')
        return
      }
      generateMutation.mutate({
        service_type: generateForm.service_type,
        items: validTokens.map(t => ({
          username: t.username.trim(),
          meta_data: t.meta_data.trim() || undefined
        }))
      })
    } else {
      generateMutation.mutate(generateForm)
    }
  }

  const addManualToken = () => {
    setManualTokens([...manualTokens, { username: '', meta_data: '' }])
  }

  const removeManualToken = (index: number) => {
    setManualTokens(manualTokens.filter((_, i) => i !== index))
  }

  const updateManualToken = (index: number, field: 'username' | 'meta_data', value: string) => {
    const updated = [...manualTokens]
    updated[index] = { ...updated[index], [field]: value }
    setManualTokens(updated)
  }

  const handleDelete = (id: string) => {
    if (window.confirm('Are you sure you want to delete this honeytoken?')) {
      deleteMutation.mutate(id)
    }
  }

  const handleBulkDelete = () => {
    if (selectedIds.size === 0) {
      alert('Please select at least one token to delete')
      return
    }
    if (window.confirm(`Are you sure you want to delete ${selectedIds.size} honeytoken(s)?`)) {
      bulkDeleteMutation.mutate(Array.from(selectedIds))
    }
  }

  const toggleSelect = (id: string) => {
    const newSelected = new Set(selectedIds)
    if (newSelected.has(id)) {
      newSelected.delete(id)
    } else {
      newSelected.add(id)
    }
    setSelectedIds(newSelected)
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === credentials?.credentials?.length) {
      setSelectedIds(new Set())
    } else {
      const allIds = new Set(credentials?.credentials?.map((c: any) => c.id) || [])
      setSelectedIds(allIds)
    }
  }

  return (
    <div className="credentials">
      <div className="header">
        <h1>Honeytokens</h1>
        <button onClick={() => setShowGenerate(!showGenerate)}>+ Generate</button>
      </div>

      {showGenerate && (
        <div className="generate-form">
          <h3>Generate Honeytokens</h3>
          
          <div className="form-group">
            <label>Service Type:</label>
            <select
              value={generateForm.service_type}
              onChange={(e) =>
                setGenerateForm({ ...generateForm, service_type: e.target.value })
              }
            >
              <option value="ssh">SSH</option>
              <option value="postgres">PostgreSQL</option>
              <option value="http">HTTP</option>
            </select>
          </div>

          <div className="form-group">
            <label>Generation Mode:</label>
            <div className="radio-group">
              <label>
                <input
                  type="radio"
                  value="auto"
                  checked={generateMode === 'auto'}
                  onChange={(e) => setGenerateMode('auto')}
                />
                Auto (random usernames)
              </label>
              <label>
                <input
                  type="radio"
                  value="manual"
                  checked={generateMode === 'manual'}
                  onChange={(e) => setGenerateMode('manual')}
                />
                Manual (custom usernames)
              </label>
            </div>
          </div>

          {generateMode === 'auto' ? (
            <div className="form-group">
              <label>Count:</label>
              <input
                type="number"
                placeholder="Count"
                value={generateForm.count}
                onChange={(e) =>
                  setGenerateForm({
                    ...generateForm,
                    count: parseInt(e.target.value) || 1,
                  })
                }
                min="1"
                max="100"
              />
            </div>
          ) : (
            <div className="manual-tokens">
              <div className="manual-tokens-header">
                <label>Custom Tokens:</label>
                <button type="button" onClick={addManualToken} className="add-token-btn">
                  + Add Token
                </button>
              </div>
              {manualTokens.map((token, index) => (
                <div key={index} className="token-row">
                  <input
                    type="text"
                    placeholder="Username (required)"
                    value={token.username}
                    onChange={(e) => updateManualToken(index, 'username', e.target.value)}
                    required
                  />
                  <input
                    type="text"
                    placeholder="Description (optional)"
                    value={token.meta_data}
                    onChange={(e) => updateManualToken(index, 'meta_data', e.target.value)}
                  />
                  {manualTokens.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeManualToken(index)}
                      className="remove-token-btn"
                    >
                      ×
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}

          <button onClick={handleGenerate} className="generate-btn">Generate</button>
        </div>
      )}

      {isLoading ? (
        <p>Loading...</p>
      ) : (
        <>
          {credentials?.credentials && credentials.credentials.length > 0 && (
            <div className="bulk-actions">
              <div className="select-controls">
                <label>
                  <input
                    type="checkbox"
                    checked={selectMode}
                    onChange={(e) => {
                      setSelectMode(e.target.checked)
                      if (!e.target.checked) {
                        setSelectedIds(new Set())
                      }
                    }}
                  />
                  Select Mode
                </label>
                {selectMode && (
                  <>
                    <button onClick={toggleSelectAll} className="select-all-btn">
                      {selectedIds.size === credentials.credentials.length ? 'Deselect All' : 'Select All'}
                    </button>
                    {selectedIds.size > 0 && (
                      <button onClick={handleBulkDelete} className="bulk-delete-btn">
                        Delete Selected ({selectedIds.size})
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>
          )}
          <div className="credentials-list">
            {credentials?.credentials && credentials.credentials.length > 0 ? credentials.credentials.map((cred: any) => (
              <div 
                key={cred.id} 
                className={`credential-card ${selectMode && selectedIds.has(cred.id) ? 'selected' : ''}`}
              >
                {selectMode && (
                  <div className="select-checkbox">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(cred.id)}
                      onChange={() => toggleSelect(cred.id)}
                    />
                  </div>
                )}
                <div className="credential-info">
                  <h3>{cred.username}</h3>
                  <p className="password-field">
                    <span className="label">Password:</span> 
                    <code>{cred.password}</code>
                  </p>
                  <p>
                    <span className="label">Service:</span> {cred.service_type}
                  </p>
                  {cred.meta_data && (
                    <div className="meta-data">
                      <span className="label">Description:</span>
                      <p className="meta-text">{cred.meta_data}</p>
                    </div>
                  )}
                  <p className={`status ${cred.used_at ? 'used' : 'unused'}`}>
                    <span className="label">Status:</span> 
                    {cred.used_at ? (
                      <span className="used-badge">⚠️ Used (Level 3 threat detected)</span>
                    ) : (
                      <span className="unused-badge">✓ Unused</span>
                    )}
                  </p>
                </div>
                {!selectMode && (
                  <div className="credential-actions">
                    <button
                      onClick={() => handleDelete(cred.id)}
                      className="delete-btn"
                      title="Delete honeytoken"
                    >
                      🗑️ Delete
                    </button>
                  </div>
                )}
              </div>
            )) : <p>No credentials yet. Generate some to get started!</p>}
          </div>
        </>
      )}
    </div>
  )
}

