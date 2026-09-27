import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { getStats } from '../api/stats';

const COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f43f5e', '#f97316', '#eab308', '#22c55e'];

const customTooltipStyle = {
  backgroundColor: '#151923',
  borderColor: '#374151',
  borderRadius: '8px',
  color: '#f3f4f6',
  fontSize: '12px',
};

export default function Stats() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    refetchInterval: 30000
  });

  const cipherData = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.cipher_suite_distribution).map(([name, value]) => ({ name, value }));
  }, [stats]);

  const dhData = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.dh_group_distribution).map(([name, value]) => ({ name, value }));
  }, [stats]);

  const pfsData = useMemo(() => {
    if (!stats) return [];
    return [
      { name: 'Enabled', value: stats.pfs_distribution.enabled || 0 },
      { name: 'Disabled', value: stats.pfs_distribution.disabled || 0 }
    ];
  }, [stats]);

  const histogramData = useMemo(() => {
    if (!stats) return [];
    return stats.score_histogram;
  }, [stats]);

  if (isLoading || !stats) {
    return (
      <div className="animate-pulse space-y-4 max-w-6xl mx-auto">
        <div className="h-64 skeleton" />
        <div className="grid grid-cols-2 gap-4">
          <div className="h-64 skeleton"/>
          <div className="h-64 skeleton"/>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight mb-1">Global Statistics</h1>
        <p className="text-gray-400 text-sm">Aggregated metrics across {stats.total_sessions} analyzed sessions</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Cipher Suite Distribution */}
        <div className="panel p-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">Cipher Suites</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={cipherData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={2} dataKey="value">
                  {cipherData.map((_, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={customTooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap gap-2 justify-center mt-2">
            {cipherData.map((entry, index) => (
              <div key={entry.name} className="flex items-center gap-1 text-xs text-gray-400 font-medium">
                <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                {entry.name}
              </div>
            ))}
          </div>
        </div>

        {/* DH Group Distribution */}
        <div className="panel p-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">DH Groups</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={dhData}>
                <XAxis dataKey="name" tick={{ fill: 'currentColor', fontSize: 12 }} axisLine={false} tickLine={false} className="text-gray-400" />
                <Tooltip cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }} contentStyle={customTooltipStyle} />
                <Bar dataKey="value" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* PFS Distribution */}
        <div className="panel p-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">PFS Adoption</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={pfsData}>
                <XAxis dataKey="name" tick={{ fill: 'currentColor', fontSize: 12 }} axisLine={false} tickLine={false} className="text-gray-400" />
                <Tooltip cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }} contentStyle={customTooltipStyle} />
                <Bar dataKey="value" fill="#10b981" radius={[4, 4, 0, 0]}>
                  {pfsData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.name === 'Enabled' ? '#10b981' : '#ef4444'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Score Histogram */}
        <div className="panel p-6 lg:col-span-3">
          <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">Security Score Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={histogramData}>
                <XAxis dataKey="bucket" tick={{ fill: 'currentColor', fontSize: 12 }} axisLine={false} tickLine={false} className="text-gray-400" />
                <YAxis tick={{ fill: 'currentColor', fontSize: 12 }} axisLine={false} tickLine={false} className="text-gray-400" />
                <Tooltip cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }} contentStyle={customTooltipStyle} />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
