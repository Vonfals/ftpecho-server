// ============================================================
// FTP Echo — PayPal + Supabase Account Management Routes
// Add these routes to your existing index.js
// ============================================================

// ============================================================
// PAYPAL HELPER
// Get PayPal access token for API calls
// ============================================================
async function getPayPalToken() {
  const auth = Buffer.from(
    process.env.PAYPAL_CLIENT_ID + ':' + process.env.PAYPAL_SECRET
  ).toString('base64');

  const base = process.env.PAYPAL_MODE === 'sandbox'
    ? 'https://api-m.sandbox.paypal.com'
    : 'https://api-m.paypal.com';

  const res = await fetch(`${base}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });

  const data = await res.json();
  return { token: data.access_token, base };
}

// ============================================================
// CREATE PAYPAL SUBSCRIPTION PLAN
// Run once to create the $12/month Pro plan
// POST /paypal/setup-plan
// ============================================================
app.post('/paypal/setup-plan', requireAuth, async (req, res) => {
  try {
    const { token, base } = await getPayPalToken();

    // Create product
    const productRes = await fetch(`${base}/v1/catalogs/products`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'FTP Echo Pro',
        description: 'FTP Echo Pro — unlimited connections, GitHub sync, terminal',
        type: 'SERVICE',
        category: 'SOFTWARE',
      }),
    });
    const product = await productRes.json();

    // Create plan
    const planRes = await fetch(`${base}/v1/billing/plans`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        product_id: product.id,
        name: 'FTP Echo Pro Monthly',
        description: 'FTP Echo Pro — $12/month',
        status: 'ACTIVE',
        billing_cycles: [{
          frequency: { interval_unit: 'MONTH', interval_count: 1 },
          tenure_type: 'REGULAR',
          sequence: 1,
          total_cycles: 0,
          pricing_scheme: {
            fixed_price: { value: '12', currency_code: 'USD' },
          },
        }],
        payment_preferences: {
          auto_bill_outstanding: true,
          setup_fee: { value: '0', currency_code: 'USD' },
          setup_fee_failure_action: 'CONTINUE',
          payment_failure_threshold: 3,
        },
      }),
    });

    const plan = await planRes.json();
    res.json({ success: true, plan_id: plan.id, product_id: product.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// CREATE SUBSCRIPTION
// Frontend calls this to start a $12/month subscription
// POST /paypal/create-subscription
// ============================================================
app.post('/paypal/create-subscription', requireAuth, async (req, res) => {
  const { plan_id, user_email } = req.body;
  try {
    const { token, base } = await getPayPalToken();

    const subRes = await fetch(`${base}/v1/billing/subscriptions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        plan_id,
        subscriber: { email_address: user_email },
        application_context: {
          brand_name: 'FTP Echo',
          locale: 'en-US',
          shipping_preference: 'NO_SHIPPING',
          user_action: 'SUBSCRIBE_NOW',
          return_url: `${process.env.FRONTEND_URL}/activate?type=pro&email=${encodeURIComponent(user_email)}`,
          cancel_url: `${process.env.FRONTEND_URL}/?cancelled=true`,
        },
      }),
    });

    const sub = await subRes.json();
    const approvalUrl = sub.links?.find(l => l.rel === 'approve')?.href;
    res.json({ success: true, approval_url: approvalUrl, subscription_id: sub.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// PAYPAL WEBHOOK
// PayPal calls this when subscription is activated or cancelled
// POST /paypal/webhook
// ============================================================
app.post('/paypal/webhook', async (req, res) => {
  const event = req.body;
  console.log('[PayPal Webhook]', event.event_type);

  try {
    const { createClient } = require('@supabase/supabase-js');
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    if (event.event_type === 'BILLING.SUBSCRIPTION.ACTIVATED') {
      const email = event.resource?.subscriber?.email_address;
      const subscriptionId = event.resource?.id;
      if (email) {
        // Find user by email and upgrade to Pro
        const { data: users } = await supabase.auth.admin.listUsers();
        const user = users?.users?.find(u => u.email === email);
        if (user) {
          await supabase.from('profiles').upsert({
            id: user.id,
            is_pro: true,
            plan: 'pro',
            paypal_subscription_id: subscriptionId,
            updated_at: new Date().toISOString(),
          });
          console.log(`[PayPal] Activated Pro for ${email}`);
        }
      }
    }

    if (event.event_type === 'BILLING.SUBSCRIPTION.CANCELLED' ||
        event.event_type === 'BILLING.SUBSCRIPTION.EXPIRED') {
      const email = event.resource?.subscriber?.email_address;
      if (email) {
        const { data: users } = await supabase.auth.admin.listUsers();
        const user = users?.users?.find(u => u.email === email);
        if (user) {
          await supabase.from('profiles').upsert({
            id: user.id,
            is_pro: false,
            plan: 'free',
            paypal_subscription_id: null,
            updated_at: new Date().toISOString(),
          });
          console.log(`[PayPal] Cancelled Pro for ${email}`);
        }
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error('[PayPal Webhook Error]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ACTIVATE FOUNDER ACCOUNT
// Called after PayPal $49 payment — creates Pro/Founder account
// POST /activate/founder
// ============================================================
app.post('/activate/founder', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const { createClient } = require('@supabase/supabase-js');
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    // Create user account
    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });

    if (authError) throw new Error(authError.message);

    // Set as founder with Pro access
    await supabase.from('profiles').upsert({
      id: authData.user.id,
      is_pro: true,
      is_founder: true,
      plan: 'founder',
      updated_at: new Date().toISOString(),
    });

    res.json({ success: true, message: 'Founder account activated successfully' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ============================================================
// GET USER PROFILE
// Returns current user's plan and profile info
// GET /profile
// ============================================================
app.get('/profile', requireAuth, async (req, res) => {
  try {
    const { createClient } = require('@supabase/supabase-js');
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', req.userId)
      .single();

    if (error) throw error;
    res.json({ success: true, profile: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// UPDATE USER PROFILE
// Update username, full_name, avatar_url
// POST /profile/update
// ============================================================
app.post('/profile/update', requireAuth, async (req, res) => {
  const { username, full_name, avatar_url } = req.body;
  try {
    const { createClient } = require('@supabase/supabase-js');
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    const { data, error } = await supabase
      .from('profiles')
      .upsert({
        id: req.userId,
        username,
        full_name,
        avatar_url,
        updated_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, profile: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ADMIN — LIST ALL USERS
// Only for you to manage accounts
// GET /admin/users
// ============================================================
app.get('/admin/users', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ENCRYPTION_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const { createClient } = require('@supabase/supabase-js');
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    const { data: profiles } = await supabase
      .from('profiles')
      .select('*')
      .order('created_at', { ascending: false });

    const { data: { users } } = await supabase.auth.admin.listUsers();

    const combined = profiles?.map(p => {
      const authUser = users?.find(u => u.id === p.id);
      return { ...p, email: authUser?.email, last_sign_in: authUser?.last_sign_in_at };
    });

    res.json({ success: true, users: combined, total: combined?.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ADMIN — UPGRADE USER TO PRO
// POST /admin/upgrade
// ============================================================
app.post('/admin/upgrade', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ENCRYPTION_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { email, plan } = req.body;
  try {
    const { createClient } = require('@supabase/supabase-js');
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    const { data: { users } } = await supabase.auth.admin.listUsers();
    const user = users?.find(u => u.email === email);
    if (!user) throw new Error('User not found');

    await supabase.from('profiles').upsert({
      id: user.id,
      is_pro: plan === 'pro' || plan === 'founder',
      is_founder: plan === 'founder',
      plan: plan,
      updated_at: new Date().toISOString(),
    });

    res.json({ success: true, message: `${email} upgraded to ${plan}` });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
