import { NextResponse } from 'next/server';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// "Ask our visa assistant" widget on the public landing page
export async function POST(req: Request) {
  const { question } = await req.json();
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: 'You are a helpful visa consultant for Austria.' },
      { role: 'user', content: question },
    ],
  });
  return NextResponse.json({ answer: completion.choices[0].message.content });
}
