'use server';
import { supabaseAdmin } from '@/lib/supabase';

export async function updateProfile(formData: FormData) {
  const id = formData.get('id') as string;
  const updates = Object.fromEntries(formData);
  delete (updates as any).id;
  await supabaseAdmin.from('profiles').update(updates).eq('id', id);
}
