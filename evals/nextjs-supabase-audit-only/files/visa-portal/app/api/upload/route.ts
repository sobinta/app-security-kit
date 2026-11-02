import { NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';

export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get('file') as File;
  const caseId = form.get('caseId') as string;
  const path = `${caseId}/${file.name}`;
  const { error } = await supabaseAdmin.storage.from('documents').upload(path, file, { upsert: true });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  await supabaseAdmin.from('documents').insert({ case_id: caseId, path, file_name: file.name });
  return NextResponse.json({ ok: true, path });
}
