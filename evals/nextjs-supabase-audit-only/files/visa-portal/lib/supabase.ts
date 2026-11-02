import { createClient } from '@supabase/supabase-js';

const url = process.env.NEXT_PUBLIC_SUPABASE_URL!;

// regular client (anon key)
export const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

// admin client — needed for the staff dashboard and document downloads
export const supabaseAdmin = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);
