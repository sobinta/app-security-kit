'use client';
import { useEffect, useState } from 'react';
import { marked } from 'marked';
import { supabase } from '@/lib/supabase';

type Case = { id: string; title: string; status: string; consultant_notes: string };

export default function Dashboard() {
  const [cases, setCases] = useState<Case[]>([]);
  useEffect(() => {
    supabase.from('cases').select('*').then(({ data }) => setCases(data ?? []));
  }, []);
  return (
    <main style={{ maxWidth: 820, margin: '24px auto' }}>
      <h1>My cases</h1>
      {cases.map((c) => (
        <section key={c.id} style={{ border: '1px solid #ddd', borderRadius: 8, padding: 16, margin: '12px 0' }}>
          <h2>{c.title} — {c.status}</h2>
          <div dangerouslySetInnerHTML={{ __html: marked.parse(c.consultant_notes || '') as string }} />
          <a href={`/api/documents/${c.id}`}>Download my documents</a>
        </section>
      ))}
    </main>
  );
}
