import { NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase';

export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'payment_intent.succeeded') {
    const caseId = event.data.object.metadata.caseId;
    await supabaseAdmin.from('payments').insert({ case_id: caseId, amount: event.data.object.amount, status: 'paid' });
    await supabaseAdmin.from('cases').update({ status: 'consultation_booked' }).eq('id', caseId);
  }
  return NextResponse.json({ received: true });
}
