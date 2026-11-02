'use client';
import { useEffect, useState } from 'react';
import { supabaseAdmin } from '@/lib/supabase';

export default function AdminPage() {
  const [profiles, setProfiles] = useState<any[]>([]);
  useEffect(() => {
    supabaseAdmin.from('profiles').select('id, full_name, email, role, passport_number').then(({ data }) => setProfiles(data ?? []));
  }, []);
  async function makeStaff(id: string) {
    await supabaseAdmin.from('profiles').update({ role: 'staff' }).eq('id', id);
  }
  return (
    <main style={{ maxWidth: 960, margin: '24px auto' }}>
      <h1>Staff dashboard</h1>
      <table>
        <tbody>
          {profiles.map((p) => (
            <tr key={p.id}><td>{p.full_name}</td><td>{p.email}</td><td>{p.passport_number}</td><td>{p.role}</td>
              <td><button onClick={() => makeStaff(p.id)}>make staff</button></td></tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
