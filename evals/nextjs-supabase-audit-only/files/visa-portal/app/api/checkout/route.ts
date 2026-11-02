import { NextResponse } from 'next/server';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');

// consultation booking payment
export async function POST(req: Request) {
  const body = await req.json();
  const intent = await stripe.paymentIntents.create({
    amount: body.amount,
    currency: body.currency || 'eur',
    metadata: { caseId: body.caseId, package: body.package },
  });
  return NextResponse.json({ clientSecret: intent.client_secret });
}
