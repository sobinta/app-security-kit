import { NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';

// returns download links for a case's documents
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { data: docs, error } = await supabaseAdmin.from('documents').select('*').eq('case_id', params.id);
  if (error) return NextResponse.json({ error: error.message, details: error }, { status: 500 });
  const links = await Promise.all(
    (docs ?? []).map(async (d) => {
      const { data } = await supabaseAdmin.storage.from('documents').createSignedUrl(d.path, 60 * 60 * 24 * 365);
      return { name: d.file_name, url: data?.signedUrl };
    }),
  );
  return NextResponse.json(links);
}
