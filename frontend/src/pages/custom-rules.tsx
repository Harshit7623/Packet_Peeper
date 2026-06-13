import React, { useState, useEffect, useCallback } from 'react';
import { apiService } from '../services/apiService';

interface Condition {
    field: string;
    operator: string;
    value: string | number;
}

interface Rule {
    id: number;
    name: string;
    description: string;
    enabled: boolean;
    severity: string;
    conditions: {
        logic: 'and' | 'or';
        checks: Condition[];
    };
    action: string;
    cooldown_seconds: number;
    trigger_count: number;
    last_triggered: string | null;
    created_at: string;
}

interface FieldInfo {
    name: string;
    label: string;
    type: string;
    operators: string[];
}

const SEVERITY_COLORS: Record<string, string> = {
    low: 'text-blue-400',
    medium: 'text-yellow-400',
    high: 'text-orange-400',
    critical: 'text-red-400',
};

const SEVERITY_BG: Record<string, string> = {
    low: 'bg-blue-400/20',
    medium: 'bg-yellow-400/20',
    high: 'bg-orange-400/20',
    critical: 'bg-red-400/20',
};

const DEFAULT_CONDITION: Condition = { field: 'dst_port', operator: 'eq', value: '' };

export default function CustomRules() {
    const [rules, setRules] = useState<Rule[]>([]);
    const [fields, setFields] = useState<FieldInfo[]>([]);
    const [loading, setLoading] = useState(true);
    const [showBuilder, setShowBuilder] = useState(false);
    const [editingId, setEditingId] = useState<number | null>(null);
    const [testResult, setTestResult] = useState<any>(null);
    const [form, setForm] = useState({
        name: '',
        description: '',
        severity: 'medium',
        logic: 'and' as 'and' | 'or',
        conditions: [{ ...DEFAULT_CONDITION }],
        action: 'alert',
        cooldown_seconds: 60,
    });

    const loadRules = useCallback(async () => {
        try {
            const data = await apiService.getCustomRules();
            setRules((data.rules || []) as unknown as Rule[]);
        } catch {
            setRules([]);
        } finally {
            setLoading(false);
        }
    }, []);

    const loadFields = useCallback(async () => {
        try {
            const data = await apiService.getCustomRuleFields();
            setFields((data.fields || []) as unknown as FieldInfo[]);
        } catch {
            setFields([]);
        }
    }, []);

    useEffect(() => {
        loadRules();
        loadFields();
    }, [loadRules, loadFields]);

    const resetForm = () => {
        setForm({
            name: '',
            description: '',
            severity: 'medium',
            logic: 'and',
            conditions: [{ ...DEFAULT_CONDITION }],
            action: 'alert',
            cooldown_seconds: 60,
        });
        setEditingId(null);
        setShowBuilder(false);
        setTestResult(null);
    };

    const addCondition = () => {
        setForm(f => ({ ...f, conditions: [...f.conditions, { ...DEFAULT_CONDITION }] }));
    };

    const removeCondition = (idx: number) => {
        setForm(f => ({
            ...f,
            conditions: f.conditions.filter((_, i) => i !== idx),
        }));
    };

    const updateCondition = (idx: number, key: keyof Condition, value: any) => {
        setForm(f => {
            const conditions = [...f.conditions];
            conditions[idx] = { ...conditions[idx], [key]: value };
            if (key === 'field') {
                const fieldInfo = fields.find(fi => fi.name === value);
                conditions[idx].operator = fieldInfo?.operators[0] || 'eq';
                conditions[idx].value = '';
            }
            return { ...f, conditions };
        });
    };

    const saveRule = async () => {
        if (!form.name.trim()) return;
        const payload = {
            name: form.name,
            description: form.description,
            severity: form.severity,
            action: form.action,
            cooldown_seconds: form.cooldown_seconds,
            conditions: {
                logic: form.logic,
                checks: form.conditions.map(c => ({
                    ...c,
                    value: fields.find(f => f.name === c.field)?.type === 'number' ? Number(c.value) : c.value,
                })),
            },
        };
        try {
            if (editingId) {
                await apiService.updateCustomRule(editingId, payload);
            } else {
                await apiService.createCustomRule(payload);
            }
            resetForm();
            loadRules();
        } catch (e) {
            console.error('Failed to save rule:', e);
        }
    };

    const editRule = (rule: Rule) => {
        setForm({
            name: rule.name,
            description: rule.description || '',
            severity: rule.severity,
            logic: rule.conditions?.logic || 'and',
            conditions: rule.conditions?.checks?.length
                ? rule.conditions.checks.map((c: Condition) => ({ ...c, value: String(c.value) }))
                : [{ ...DEFAULT_CONDITION }],
            action: rule.action,
            cooldown_seconds: rule.cooldown_seconds,
        });
        setEditingId(rule.id);
        setShowBuilder(true);
        setTestResult(null);
    };

    const toggleRule = async (id: number) => {
        try {
            await apiService.toggleCustomRule(id);
            loadRules();
        } catch (e) {
            console.error('Failed to toggle rule:', e);
        }
    };

    const deleteRule = async (id: number) => {
        try {
            await apiService.deleteCustomRule(id);
            loadRules();
        } catch (e) {
            console.error('Failed to delete rule:', e);
        }
    };

    const testCurrentRule = async () => {
        try {
            const result = await apiService.testCustomRule({
                logic: form.logic,
                checks: form.conditions.map(c => ({
                    ...c,
                    value: fields.find(f => f.name === c.field)?.type === 'number' ? Number(c.value) : c.value,
                })),
            });
            setTestResult(result);
        } catch (e) {
            console.error('Failed to test rule:', e);
        }
    };

    const getOperatorLabel = (op: string) => {
        const labels: Record<string, string> = {
            eq: '=', neq: '!=', gt: '>', gte: '>=', lt: '<', lte: '<=',
            contains: 'contains', startswith: 'starts with', endswith: 'ends with',
            regex: '~regex', in: 'in', not_in: 'not in', cidr: 'in CIDR',
        };
        return labels[op] || op;
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
            </div>
        );
    }

    return (
        <div className="p-6 space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white">Custom Alert Rules</h1>
                    <p className="text-gray-400 text-sm mt-1">Define custom detection rules for network traffic</p>
                </div>
                <button
                    onClick={() => { resetForm(); setShowBuilder(true); }}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                >
                    + New Rule
                </button>
            </div>

            {showBuilder && (
                <div className="bg-gray-800/80 backdrop-blur rounded-xl border border-gray-700 p-6 space-y-4">
                    <div className="flex items-center justify-between">
                        <h2 className="text-lg font-semibold text-white">
                            {editingId ? 'Edit Rule' : 'Create Rule'}
                        </h2>
                        <button onClick={resetForm} className="text-gray-400 hover:text-white text-xl">&times;</button>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">Rule Name</label>
                            <input
                                value={form.name}
                                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                                className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 focus:border-blue-500 outline-none"
                                placeholder="e.g. Block SSH from external"
                            />
                        </div>
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">Severity</label>
                            <select
                                value={form.severity}
                                onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                                className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 focus:border-blue-500 outline-none"
                            >
                                {['low', 'medium', 'high', 'critical'].map(s => (
                                    <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                                ))}
                            </select>
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm text-gray-400 mb-1">Description</label>
                        <input
                            value={form.description}
                            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                            className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 focus:border-blue-500 outline-none"
                            placeholder="What this rule detects..."
                        />
                    </div>

                    <div>
                        <div className="flex items-center justify-between mb-2">
                            <label className="text-sm text-gray-400">Conditions</label>
                            <div className="flex items-center gap-2">
                                <span className="text-xs text-gray-500">Logic:</span>
                                <select
                                    value={form.logic}
                                    onChange={e => setForm(f => ({ ...f, logic: e.target.value as 'and' | 'or' }))}
                                    className="bg-gray-700 text-white rounded px-2 py-1 text-xs border border-gray-600 outline-none"
                                >
                                    <option value="and">AND (all must match)</option>
                                    <option value="or">OR (any can match)</option>
                                </select>
                            </div>
                        </div>

                        <div className="space-y-2">
                            {form.conditions.map((cond, idx) => (
                                <div key={idx} className="flex items-center gap-2">
                                    <select
                                        value={cond.field}
                                        onChange={e => updateCondition(idx, 'field', e.target.value)}
                                        className="bg-gray-700 text-white rounded px-2 py-1.5 text-sm border border-gray-600 outline-none flex-1"
                                    >
                                        {fields.map(f => (
                                            <option key={f.name} value={f.name}>{f.label}</option>
                                        ))}
                                    </select>
                                    <select
                                        value={cond.operator}
                                        onChange={e => updateCondition(idx, 'operator', e.target.value)}
                                        className="bg-gray-700 text-white rounded px-2 py-1.5 text-sm border border-gray-600 outline-none w-28"
                                    >
                                        {(fields.find(f => f.name === cond.field)?.operators || []).map(op => (
                                            <option key={op} value={op}>{getOperatorLabel(op)}</option>
                                        ))}
                                    </select>
                                    <input
                                        value={cond.value}
                                        onChange={e => updateCondition(idx, 'value', e.target.value)}
                                        className="bg-gray-700 text-white rounded px-2 py-1.5 text-sm border border-gray-600 outline-none flex-1"
                                        placeholder="Value"
                                    />
                                    {form.conditions.length > 1 && (
                                        <button
                                            onClick={() => removeCondition(idx)}
                                            className="text-red-400 hover:text-red-300 px-2"
                                        >
                                            &times;
                                        </button>
                                    )}
                                </div>
                            ))}
                        </div>
                        <button
                            onClick={addCondition}
                            className="mt-2 text-sm text-blue-400 hover:text-blue-300"
                        >
                            + Add Condition
                        </button>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">Action</label>
                            <select
                                value={form.action}
                                onChange={e => setForm(f => ({ ...f, action: e.target.value }))}
                                className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 outline-none"
                            >
                                <option value="alert">Alert Only</option>
                                <option value="log">Log Only</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">Cooldown (seconds)</label>
                            <input
                                type="number"
                                value={form.cooldown_seconds}
                                onChange={e => setForm(f => ({ ...f, cooldown_seconds: parseInt(e.target.value) || 60 }))}
                                className="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 outline-none"
                                min={1}
                            />
                        </div>
                    </div>

                    <div className="flex gap-3 pt-2">
                        <button
                            onClick={saveRule}
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                        >
                            {editingId ? 'Update Rule' : 'Create Rule'}
                        </button>
                        <button
                            onClick={testCurrentRule}
                            className="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded-lg transition-colors"
                        >
                            Test Rule
                        </button>
                        <button onClick={resetForm} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors">
                            Cancel
                        </button>
                    </div>

                    {testResult && (
                        <div className="bg-gray-900 rounded-lg p-4 border border-gray-600">
                            <h3 className="text-sm font-semibold text-white mb-2">Test Results</h3>
                            <div className="grid grid-cols-3 gap-4 text-center">
                                <div>
                                    <div className="text-2xl font-bold text-white">{testResult.total_packets}</div>
                                    <div className="text-xs text-gray-400">Total Packets</div>
                                </div>
                                <div>
                                    <div className="text-2xl font-bold text-yellow-400">{testResult.matching_packets}</div>
                                    <div className="text-xs text-gray-400">Matches</div>
                                </div>
                                <div>
                                    <div className="text-2xl font-bold text-blue-400">{testResult.match_rate}%</div>
                                    <div className="text-xs text-gray-400">Match Rate</div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {rules.length === 0 ? (
                <div className="bg-gray-800/50 rounded-xl border border-gray-700 p-12 text-center">
                    <div className="text-gray-500 text-lg mb-2">No custom rules defined</div>
                    <p className="text-gray-600 text-sm">Create a rule to add custom detection logic for your network traffic</p>
                </div>
            ) : (
                <div className="space-y-3">
                    {rules.map(rule => (
                        <div
                            key={rule.id}
                            className={`bg-gray-800/80 backdrop-blur rounded-xl border p-4 ${
                                rule.enabled ? 'border-gray-700' : 'border-gray-700/50 opacity-60'
                            }`}
                        >
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <button
                                        onClick={() => toggleRule(rule.id)}
                                        className={`w-10 h-5 rounded-full transition-colors relative ${
                                            rule.enabled ? 'bg-blue-600' : 'bg-gray-600'
                                        }`}
                                    >
                                        <div
                                            className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                                                rule.enabled ? 'translate-x-5' : 'translate-x-0.5'
                                            }`}
                                        />
                                    </button>
                                    <div>
                                        <h3 className="text-white font-medium">{rule.name}</h3>
                                        {rule.description && (
                                            <p className="text-gray-400 text-sm">{rule.description}</p>
                                        )}
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_BG[rule.severity]} ${SEVERITY_COLORS[rule.severity]}`}>
                                        {rule.severity}
                                    </span>
                                    <span className="text-gray-500 text-xs">
                                        Triggered: {rule.trigger_count || 0}
                                    </span>
                                    <button
                                        onClick={() => editRule(rule)}
                                        className="text-gray-400 hover:text-white text-sm"
                                    >
                                        Edit
                                    </button>
                                    <button
                                        onClick={() => deleteRule(rule.id)}
                                        className="text-red-400 hover:text-red-300 text-sm"
                                    >
                                        Delete
                                    </button>
                                </div>
                            </div>
                            <div className="mt-2 flex items-center gap-2 text-xs text-gray-500">
                                <span>Logic: {rule.conditions?.logic?.toUpperCase() || 'AND'}</span>
                                <span>|</span>
                                <span>Conditions: {rule.conditions?.checks?.length || 0}</span>
                                <span>|</span>
                                <span>Cooldown: {rule.cooldown_seconds}s</span>
                                {rule.last_triggered && (
                                    <>
                                        <span>|</span>
                                        <span>Last: {new Date(rule.last_triggered).toLocaleString()}</span>
                                    </>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
