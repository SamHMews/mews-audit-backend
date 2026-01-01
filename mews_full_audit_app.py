<!DOCTYPE html>
<html lang="en" class="no-js">
<head>
  <!-- Sam & Georgia — Gozo Wedding (single-file site, updated: Google Maps + goldfish + RSVP menu) -->
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#F9F6F0" />
  <title>Sam &amp; Georgia — Gozo Wedding</title>
  <meta name="description" content="Sam & Georgia's Mediterranean wedding in Gozo · dates, travel, venues and RSVP — warm, coastal and timeless." />

  <!-- Social sharing -->
  <meta property="og:type" content="website" />
  <meta property="og:title" content="Sam &amp; Georgia — Gozo Wedding" />
  <meta property="og:description" content="Join us in Gozo · dates, travel, venue & RSVP." />
  <meta property="og:image" content="https://upload.wikimedia.org/wikipedia/commons/e/e8/Ramla_Bay.jpg" />
  <meta name="twitter:card" content="summary_large_image" />

  <link rel="canonical" href="https://example.com/" />

  <!-- Favicon: cartoon sun (SVG) -->
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Ccircle cx='32' cy='32' r='14' fill='%23E6B655'/%3E%3Cg stroke='%23E6B655' stroke-width='4'%3E%3Cline x1='32' y1='4' x2='32' y2='16'/%3E%3Cline x1='32' y1='48' x2='32' y2='60'/%3E%3Cline x1='4' y1='32' x2='16' y2='32'/%3E%3Cline x1='48' y1='32' x2='60' y2='32'/%3E%3Cline x1='12' y1='12' x2='20' y2='20'/%3E%3Cline x1='44' y1='44' x2='52' y2='52'/%3E%3Cline x1='12' y1='52' x2='20' y2='44'/%3E%3Cline x1='44' y1='20' x2='52' y2='12'/%3E%3C/g%3E%3C/svg%3E" />

  <!-- Google Fonts -->
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;500;600;700&family=Parisienne&family=Raleway:wght@300;400;500;600&display=swap" rel="stylesheet">

  <style>
    :root{
      --terracotta:#A75A32; --gold:#E6B655; --seafoam:#83B8B4; --olive:#7E8C4F; --cream:#F9F6F0; --teal:#2F4A4E; --ink:#243133;
      --maxw:1100px; --radius:18px; --shadow:0 10px 30px rgba(47,74,78,.12);
      --hero-image:url('data:image/svg+xml;utf8,\
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800">\
          <defs>\
            <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">\
              <stop offset="0%" stop-color="%2383B8B4"/>\
              <stop offset="60%" stop-color="%23F9F6F0"/>\
            </linearGradient>\
            <linearGradient id="sea" x1="0" y1="0" x2="1" y2="0">\
              <stop offset="0%" stop-color="%232F4A4E"/>\
              <stop offset="100%" stop-color="%2383B8B4"/>\
            </linearGradient>\
          </defs>\
          <rect width="1200" height="800" fill="url(%23sky)"/>\
          <path d="M0,520 C200,480 400,560 600,520 C800,480 1000,560 1200,520 L1200,800 L0,800 Z" fill="url(%23sea)" opacity="0.85"/>\
          <circle cx="980" cy="140" r="55" fill="%23E6B655" opacity="0.9"/>\
        </svg>');
    }

    html{scroll-behavior:smooth}
    body{
      margin:0;background:var(--cream);color:var(--teal);
      font-family:'Raleway',system-ui,Segoe UI,Arial,sans-serif;line-height:1.6;
      cursor:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='26' height='26' viewBox='0 0 64 64'%3E%3Ccircle cx='32' cy='32' r='10' fill='%23E6B655'/%3E%3Cg stroke='%23E6B655' stroke-width='4'%3E%3Cline x1='32' y1='2' x2='32' y2='14'/%3E%3Cline x1='32' y1='50' x2='32' y2='62'/%3E%3Cline x1='2' y1='32' x2='14' y2='32'/%3E%3Cline x1='50' y1='32' x2='62' y2='32'/%3E%3Cline x1='10' y1='10' x2='18' y2='18'/%3E%3Cline x1='46' y1='46' x2='54' y2='54'/%3E%3Cline x1='10' y1='54' x2='18' y2='46'/%3E%3Cline x1='46' y1='18' x2='54' y2='10'/%3E%3C/g%3E%3C/svg%3E") 13 13, auto
    }

    .container{max-width:var(--maxw);margin:0 auto;padding:0 20px}
    .section{padding:72px 0;position:relative;scroll-margin-top:84px}
    @media(min-width:900px){.section{padding:120px 0}}

    /* Header */
    header{position:sticky;top:0;z-index:1000;background:color-mix(in srgb,var(--cream) 90%,white 10%);border-bottom:1px solid #e8e3d9;backdrop-filter:blur(6px)}
    .nav{display:flex;align-items:center;justify-content:space-between;gap:14px;height:64px}
    .brand{display:inline-flex;align-items:center;gap:.6rem;color:var(--terracotta);text-decoration:none;font-weight:700}
    .brand .logo{width:24px;height:24px}
    .burger{display:inline-flex;width:40px;height:40px;border:1px solid #d8d3c8;border-radius:12px;background:#fff;align-items:center;justify-content:center}
    .burger span{width:18px;height:2px;background:var(--teal);position:relative;display:block}
    .burger span::before,.burger span::after{content:"";position:absolute;left:0;right:0;height:2px;background:var(--teal)}
    .burger span::before{top:-6px}.burger span::after{top:6px}
    nav ul{list-style:none;margin:0;padding:0;display:none;position:absolute;top:64px;left:16px;right:16px;background:#fff;border:1px solid #e8e3d9;border-radius:14px;box-shadow:var(--shadow)}
    nav ul.open{display:block}
    nav a{text-decoration:none;color:var(--teal);font-weight:600;display:block;padding:12px 14px}
    nav a:hover{color:var(--terracotta)}
    @media(min-width:880px){.burger{display:none} nav ul{position:static;display:flex;border:none;box-shadow:none} nav a{padding:0;margin-left:20px}}

    /* HERO */
    .hero{
      display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;
      min-height:90vh;padding:100px 20px 60px;position:relative;overflow:hidden;
      background-image:linear-gradient(to bottom,rgba(249,246,240,.65),rgba(249,246,240,.12)),var(--hero-image);
      background-size:cover;background-position:center;background-attachment:scroll
    }
    @media(min-width:900px){.hero{min-height:86vh;background-attachment:fixed;padding:160px 20px 100px}}
    @media (prefers-reduced-motion: reduce){.hero{background-attachment:scroll}}
    .hero .eyebrow{text-transform:uppercase;letter-spacing:.18em;font-size:.8rem;color:var(--olive)}
    .hero .display{font-family:'Cormorant Garamond',serif;color:var(--terracotta);font-size:clamp(40px,8vw,72px);margin:12px 0 8px}
    .hero .tagline{margin-bottom:24px;color:var(--teal);font-style:italic}

    /* Countdown */
    .countdown{display:flex;flex-direction:column;align-items:center;gap:8px;margin-bottom:24px}
    .countdown .unit{background:#fff;border:1px solid #eadfcd;border-radius:12px;padding:8px 14px;min-width:120px}
    .countdown .num{font-weight:700;color:var(--terracotta);font-size:1.4rem}
    @media(min-width:600px){.countdown{flex-direction:row}}

    /* CTAs */
    .cta-row{display:flex;flex-direction:column;align-items:center;gap:12px}
    @media(min-width:600px){.cta-row{flex-direction:row}}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:.6rem;border-radius:999px;padding:14px 18px;border:1px solid var(--terracotta);font-weight:600;text-decoration:none;box-shadow:var(--shadow);transition:transform .2s,box-shadow .2s,background .3s}
    .btn{background:var(--terracotta);color:#fff}
    .btn.alt{background:#fff;color:var(--terracotta)}
    .btn:hover{transform:translateY(-2px);box-shadow:0 14px 40px rgba(167,90,50,.25);background:#964c28}

    /* Story / Cards */
    h2,h3{font-family:'Cormorant Garamond',serif;color:var(--ink)}
    h2{font-size:clamp(26px,3.6vw,44px);margin:0 0 14px}
    h3{font-size:clamp(22px,2.2vw,28px);margin:0 0 10px}
    .accent{font-family:'Parisienne',cursive;font-size:clamp(24px,3vw,42px);color:var(--terracotta)}
    .story-grid{display:grid;gap:24px}
    @media(min-width:900px){.story-grid{grid-template-columns:1.2fr 1fr;align-items:center;gap:42px}}
    .card{background:#fff;border:1px solid #efe9de;border-radius:var(--radius);box-shadow:var(--shadow);padding:22px}
    .media{position:relative;overflow:hidden;border-radius:var(--radius);box-shadow:var(--shadow)}
    .media img{width:100%;height:auto;display:block}
    .pill{display:inline-block;border-radius:999px;border:1px solid var(--seafoam);padding:6px 12px;font-size:.9rem;color:var(--teal);background:#ffffffb3;margin-right:6px}

    /* Dates */
    .dates{background:linear-gradient(180deg,#fff,#f6f2ea)}
    .dates-grid{display:grid;gap:22px}
    @media(min-width:980px){.dates-grid{grid-template-columns:1.1fr .9fr;gap:32px}}
    .map-card{position:relative;background:#fff;border:1px solid #eadfcd;border-radius:18px;padding:12px;box-shadow:var(--shadow)}
    .map-embed{border-radius:14px;overflow:hidden;aspect-ratio:4/3;background:#e8f3f2}
    .map-embed iframe{width:100%;height:100%;border:0;display:block}
    .map-legend{position:absolute;left:14px;bottom:12px;background:#ffffffd8;border:1px solid #eadfcd;border-radius:12px;padding:6px 10px;font-size:.85rem;color:#2F4A4E}
    .map-dot{display:inline-block;width:10px;height:10px;background:#A75A32;border-radius:50%;border:2px solid #fff;box-shadow:0 0 0 1px #A75A32;margin-right:.4rem}

    /* Travel / Stay */
    .travel-grid{display:grid;gap:22px}
    @media(min-width:900px){.travel-grid{grid-template-columns:repeat(3,1fr)}}
    .tip{background:#fff;border:1px solid #efe9de;border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}

    .stay-grid{display:grid;gap:22px}
    @media(min-width:980px){.stay-grid{grid-template-columns:1.1fr .9fr;gap:28px}}
    .stay-list{margin:0;padding-left:18px}
    .stay-list li{margin:8px 0}

    /* RSVP */
    .rsvp{background:linear-gradient(180deg,#f6f2ea,#fff)}
    form{display:grid;gap:14px;max-width:720px;margin:16px auto 0}
    input,select,textarea{width:100%;border:1px solid #e5ded2;border-radius:12px;padding:14px;font:inherit;background:#fff;min-height:48px;font-size:16px}
    .fieldset{border:1px dashed #eadfcd;border-radius:14px;padding:12px}
    .fieldset legend{padding:0 6px;color:var(--terracotta);font-weight:600}
    .hidden{display:none !important}

    /* Gallery */
    .gallery-grid{display:grid;grid-template-columns:1fr;gap:12px}
    @media(min-width:800px){.gallery-grid{grid-template-columns:repeat(4,1fr);gap:14px}}
    .gallery-grid img{width:100%;height:100%;object-fit:cover;border-radius:14px;box-shadow:var(--shadow)}

    /* Footer */
    footer{background:var(--teal);color:#eaf3f2;padding:50px 0;position:relative;overflow:hidden}
    .footer-motif{position:absolute;inset:0;opacity:.08;background-image:radial-gradient(circle at 20% 10%,#fff 1px,transparent 2px),radial-gradient(circle at 80% 70%,#fff 1px,transparent 2px);background-size:120px 120px,160px 160px}

    /* Reveal */
    .reveal{opacity:0;transform:translateY(14px);transition:opacity .8s,transform .8s}
    .reveal.visible{opacity:1;transform:translateY(0)}

    /* Sunlight hover */
    .sunlight{position:fixed;inset:0;pointer-events:none;z-index:5;mix-blend-mode:soft-light;background:
      radial-gradient(420px 420px at var(--x,50%) var(--y,50%), rgba(230,182,85,.55), rgba(230,182,85,.18) 40%, rgba(230,182,85,0) 65%),
      radial-gradient(800px 800px at var(--x,50%) var(--y,50%), rgba(255,255,220,.15), rgba(255,255,220,0) 50%);
      transition:background .08s ease}
    @media(prefers-reduced-motion:reduce){.sunlight{transition:none;display:none}}

    /* Audio toggle */
    .audio-toggle{position:fixed;right:14px;bottom:14px;z-index:1200;background:#fff;border:1px solid #e5ded2;border-radius:999px;padding:10px 14px;box-shadow:var(--shadow);display:flex;gap:.5rem;align-items:center}
    .audio-toggle button{all:unset;cursor:pointer;font-weight:700;color:var(--terracotta)}
    /* Mobile gold fish effect (mobile-only, touch-trigger) */
    .goldfish{
      position:fixed; left:0; top:0;
      pointer-events:none;
      z-index:9999;
      width:82px; height:auto;          /* smaller + more realistic */
      opacity:0;
      transform:translate3d(var(--sx,0px), var(--sy,0px), 0) scale(var(--sc,1));
      will-change: transform, opacity;
      filter: drop-shadow(0 4px 10px rgba(0,0,0,.18));
    }

    .goldfish svg{ display:block; width:100%; height:auto; }
    .goldfish .fish-wrap{
      transform-origin: 50% 50%;
      transform: scaleX(var(--flip, 1));
    }
    .goldfish .tail{
      transform-origin: 12% 50%;
      animation: fish-tail 220ms ease-in-out infinite;
    }
    .goldfish .fin{
      transform-origin: 40% 50%;
      animation: fish-fin 380ms ease-in-out infinite;
      opacity: .85;
    }

    /* main swim: darts to the touch point, then bolts off-screen */
    .goldfish.swimming{
  animation:
    fish-appear 120ms ease-out forwards,
    fish-path var(--dur, 3200ms) cubic-bezier(.2,.8,.2,1) forwards,
    fish-fade 280ms ease-in forwards;
  animation-delay:
    0ms,
    70ms,
    calc(var(--dur, 3200ms) - 260ms);
}

/* subtle up/down as it swims */
    .goldfish.swimming .fish-wrap{
      animation: fish-bob 520ms ease-in-out infinite;
    }

    @keyframes fish-appear{
      from{ opacity:0; transform:translate3d(var(--sx), var(--sy), 0) scale(.92); }
      to  { opacity:.98; transform:translate3d(var(--sx), var(--sy), 0) scale(1); }
    }

    /* keyframe path with a "curious dart" to the tap point, micro-pause, then escape */
    @keyframes fish-path{
      0%   { transform:translate3d(var(--sx), var(--sy), 0) scale(1); }
      18%  { transform:translate3d(var(--mx), var(--my), 0) scale(1); }
      24%  { transform:translate3d(var(--mx), var(--my), 0) scale(1); }
      100% { transform:translate3d(var(--ex), var(--ey), 0) scale(.96); }
    }

    @keyframes fish-fade{
      from{ opacity:.98; }
      to  { opacity:0; }
    }
    @keyframes fish-bob{
      0%   { transform:translate3d(0,0,0) rotate(-1deg); }
      50%  { transform:translate3d(0,-8px,0) rotate(1deg); }
      100% { transform:translate3d(0,0,0) rotate(-1deg); }
    }
    @keyframes fish-tail{
      0%   { transform:rotate(10deg); }
      50%  { transform:rotate(-14deg); }
      100% { transform:rotate(10deg); }
    }
    @keyframes fish-fin{
      0%   { transform:rotate(6deg); }
      50%  { transform:rotate(-10deg); }
      100% { transform:rotate(6deg); }
    }

    @media(min-width:768px){ .goldfish{ display:none } } /* mobile-only */
    @media (prefers-reduced-motion: reduce){
      .goldfish, .goldfish *{ animation:none !important; }
    }
  
/* Visibility safeguard */
section p,
section ul,
section ol,
section li,
section figure,
section img,
section .card,
section .container {
  display: block;
  opacity: 1;
  visibility: visible;
}

</style>

  <!-- Event structured data -->
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Event",
    "name": "Sam & Georgia — Wedding",
    "startDate": "2026-09-10T14:00:00+02:00",
    "endDate": "2026-09-10T20:00:00+02:00",
    "eventStatus": "https://schema.org/EventScheduled",
    "eventAttendanceMode": "https://schema.org/OfflineEventAttendanceMode",
    "location": {
      "@type": "Place",
      "name": "Kantra Beach Club",
      "address": "Triq Ta’ Ċenċ (by Mġarr ix-Xini), Sannat, Gozo"
    },
    "image": [
      "https://upload.wikimedia.org/wikipedia/commons/e/e8/Ramla_Bay.jpg"
    ],
    "description": "Our Mediterranean wedding in Gozo: dates, travel, venue and RSVP."
  }
  </script>
</head>
<body>
  <div class="sunlight" aria-hidden="true"></div>

  <!-- Header / Nav -->
  <header>
    <div class="container nav" role="navigation" aria-label="Main navigation">
      <a class="brand" href="#welcome" aria-label="Go to top">
        <svg class="logo" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2c5 0 9 4 9 9 0 6-9 11-9 11S3 17 3 11c0-5 4-9 9-9Zm0 3c-3.3 0-6 2.7-6 6 0 3.9 3.6 7.4 6 9 2.4-1.6 6-5.1 6-9 0-3.3-2.7-6-6-6Z"/></svg>
        <span>Sam &amp; Georgia</span>
      </a>
      <button class="burger" aria-label="Open menu" aria-controls="menu" aria-expanded="false"><span></span></button>
      
    </div>
  </header>

  <!-- Hero -->
  <main id="welcome" class="hero" role="main" aria-label="Welcome">
    <p class="eyebrow">Gozo, Malta</p>
    <h1 class="display">Sam &amp; Georgia</h1>
    <p class="tagline"><em>Under the Gozo sun — warm seas, good food, and all our favourite people.</em></p>

    <div class="countdown" aria-live="polite" aria-label="Countdown to our wedding">
      <div class="unit"><div class="num" id="d">—</div><div class="lbl">days</div></div>
      <div class="unit"><div class="num" id="h">—</div><div class="lbl">hours</div></div>
      <div class="unit"><div class="num" id="m">—</div><div class="lbl">mins</div></div>
      <div class="unit"><div class="num" id="s">—</div><div class="lbl">secs</div></div>
    </div>

    <div class="cta-row">
      <a class="btn alt" href="#story">Discover our story</a>
      <a class="btn" href="#rsvp">Join us under the Gozo sun</a>
    </div>

    <!-- Add-to-calendar quick link -->
    <p style="margin-top:14px"><a id="ics" class="btn alt" download="sam-georgia-gozo.ics" href="#">Add to calendar</a></p>
  </main>

  <!-- Our Story -->
  <section id="story" class="section" aria-labelledby="story-title">
    <div class="container">
      <h2 id="story-title">Our Story</h2>
      <p class="accent">Our love story started here — and we're so excited to return.</p>
      <div class="story-grid reveal">
        <div class="card">
          <h3>From Bristol to Gozo</h3>
          <p><strong>How we met: </strong> We met at LeoVegas, G fell in love with Sam because he is an absolute unit and really cool.</p>
          <p><strong>The engagement: Bare romance</strong> &ndash; we’ll fill this in soon.</p>
          <div style="margin-top:10px">
            <span class="pill">Golden beaches</span>
            <span class="pill">Olive groves</span>
            <span class="pill">Sunlit days</span>
          </div>
        </div>
        <figure class="media">
          <img loading="lazy" width="1280" height="853" src="assets/images/LeoVegas.jpeg" alt="A favourite moment from our travels">
        </figure>
      </div>
      <div class="card reveal" style="margin-top:26px">
        <h3>Moments that matter</h3>
        <ol style="margin:0; padding-left:18px">
          <li><strong>First meeting:</strong> (date coming soon)</li>
          <li><strong>Engagement:</strong> (date coming soon)</li>
          <li><strong>Wedding:</strong> <span id="timeline-wedding-date">10 September 2026</span></li>
        </ol>
      </div>
    </div>
  </section>

  <!-- Wedding Dates with Google Maps -->
  <section id="dates" class="section dates" aria-labelledby="dates-title">
    <div class="container">
      <h2 id="dates-title">The Wedding Dates</h2>

      <div class="dates-grid">
        <!-- Left: details -->
        <div class="card reveal">
          <h3>Ceremony</h3>
          <p>Details to follow — time and location for the vows will be shared here.</p>

          <h3 style="margin-top:18px">Reception — Kantra Beach Club</h3>
          <p>
            Kantra Beach Club, Triq Ta’ Ċenċ (by Mġarr ix-Xini), Sannat, Gozo.
            <a href="https://www.tripadvisor.co.uk/Restaurant_Review-g230154-d4400180-Reviews-Kantra_Beach_Club-Sannat_Island_of_Gozo.html" target="_blank" rel="noopener">Tripadvisor</a>
          </p>

          <hr style="border:0;height:1px;background:linear-gradient(90deg,transparent,var(--gold),transparent);margin:18px 0" />
          <h3>Local highlights</h3>
          <ul>
            <li>Mġarr ix-Xini inlet — swim &amp; snorkel</li>
            <li>Ramla Bay — red sand beach</li>
            <li>Xlendi — sunsets &amp; seafront strolls</li>
          </ul>

          <p style="margin-top:14px">
            <a class="btn alt" href="https://www.google.com/maps?q=36.017361,14.271833" target="_blank" rel="noopener">
              View in Google Maps
            </a>
          </p>
        </div>

        <!-- Right: Google Maps widget -->
        <div class="map-card reveal" aria-label="Google map of Kantra Beach Club, Gozo">
          <div class="map-embed">
            <iframe
              loading="lazy"
              allowfullscreen
              referrerpolicy="no-referrer-when-downgrade"
              src="https://www.google.com/maps?q=36.017361,14.271833&z=16&output=embed"
              title="Kantra Beach Club location on Google Maps">
            </iframe>
          </div>
          <div class="map-legend"><span class="map-dot"></span>Reception</div>
        </div>
      </div>
    </div>
  </section>

    <!-- How to Get There -->
  <section id="travel" class="section" aria-labelledby="travel-title">
    <div class="container">
      <h2 id="travel-title">How to Get There</h2>
      <p class="accent">Three simple steps — fly to Malta, get to the right terminal, then hop over to Gozo.</p>

      <div class="travel-grid">
        <div class="tip reveal">
          <h3>Step 1: Fly to Malta (MLA)</h3>
          <ul class="stay-list">
            <li>Book flights to <strong>Malta International Airport (MLA)</strong>.</li>
            <li><strong>Car hire:</strong> hiring at the airport is the easiest way to explore Gozo (and it makes ferry travel straightforward).</li>
            <li>If you’re not hiring a car, taxis and ride-hailing can get you into Valletta for the fast ferry.</li>
          </ul>
          <figure class="media" style="margin-top:14px">
            <img loading="lazy" width="1280" height="853" src="assets/images/London.jpeg" alt="Travel moments together">
          </figure>
        </div>

        <div class="tip reveal">
          <h3>Step 2: Getting to the Ferry Terminals</h3>
          <ul class="stay-list">
            <li><strong>Option A — Car ferry terminal (Ċirkewwa):</strong> best if you have a hire car. Drive from the airport to Ċirkewwa and take the <em>Gozo Channel</em> car ferry.</li>
            <li><strong>Option B — Valletta fast ferry:</strong> best if you’re travelling without a car. Head to Valletta and take the <em>Gozo Highspeed</em> passenger ferry.</li>
            <li>Both options get you to Gozo — pick the one that fits your plans.</li>
          </ul>
          <figure class="media" style="margin-top:14px">
            <img loading="lazy" width="1280" height="853" src="assets/images/Canada.jpeg" alt="A scenic travel photo">
          </figure>
        </div>

        <div class="tip reveal">
          <h3>Step 3: Ferry to Gozo (timetables)</h3>
          <ul class="stay-list">
            <li><strong>Car ferry (Ċirkewwa ↔ Mġarr):</strong> frequent sailings, ~25 minutes crossing.</li>
            <li><strong>Fast ferry (Valletta ↔ Mġarr):</strong> passenger-only, typically ~45 minutes.</li>
            <li>Check live times before you travel:</li>
            <li>
              <a href="https://www.gozochannel.com/ferry/schedule/" target="_blank" rel="noopener">Gozo Channel (car ferry) timetable</a>
              &nbsp;•&nbsp;
              <a href="https://gozohighspeed.com/pages/schedule" target="_blank" rel="noopener">Gozo Highspeed (fast ferry) timetable</a>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </section>


  
  <!-- Getting Around -->
  <section id="getting-around" class="section" aria-labelledby="around-title">
    <div class="container">
      <h2 id="around-title">Getting Around Gozo</h2>
      <p class="accent">Gozo is small — you’re never far from the good stuff.</p>

      <div class="stay-grid">
        <div class="card reveal">
          <h3>Best option: car hire</h3>
          <ul class="stay-list">
            <li>Most flexible for beaches, dinner plans, and exploring.</li>
            <li>Driving is relaxed and distances are short.</li>
          </ul>

          <h3 style="margin-top:12px">Also works well</h3>
          <ul class="stay-list">
            <li><strong>Taxis / ride-hailing:</strong> local taxis and ride-hailing in Malta can help for airport/Valletta legs.</li>
            <li><strong>Buses:</strong> inexpensive routes between towns (allow extra time).</li>
          </ul>
        </div>

        <figure class="media reveal" style="margin:0">
          <img loading="lazy" width="1280" height="853" src="assets/images/Kayak.jpeg" alt="On the water in the sun">
        </figure>
      </div>
    </div>
  </section>

  <!-- Weather -->
  <section id="weather" class="section" aria-labelledby="weather-title">
    <div class="container">
      <h2 id="weather-title">Weather in Early September</h2>
      <p class="accent">Typically warm days and balmy evenings — perfect for long dinners.</p>

      <div class="stay-grid">
        <div class="card reveal">
          <ul class="stay-list">
            <li>Bring light layers for evenings by the sea.</li>
            <li>Sun protection is a must (hat + SPF).</li>
            <li>Pack a light rain layer just in case.</li>
          </ul>
          <p style="margin-top:10px">We’ll share a quick forecast snapshot closer to the date.</p>
        </div>

        <figure class="media reveal" style="margin:0">
          <img loading="lazy" width="1280" height="853" src="assets/images/Winter%20Wonderland.jpeg" alt="A playful contrast: definitely not the Gozo forecast">
        </figure>
      </div>
    </div>
  </section>

  <!-- Attire -->
  <section id="attire" class="section" aria-labelledby="attire-title">
    <div class="container">
      <h2 id="attire-title">Wedding Attire</h2>
      <p class="accent">Smart, comfortable, and summer-friendly.</p>

      <div class="stay-grid">
        <div class="card reveal">
          <h3>Guidance</h3>
          <ul class="stay-list">
            <li><strong>Ceremony:</strong> smart summer wedding attire.</li>
            <li><strong>Footwear:</strong> Gozo is charmingly uneven in places — block heels, wedges, or smart flats work best.</li>
            <li><strong>Evening:</strong> a light layer is handy once the sun dips.</li>
          </ul>
        </div>

        <figure class="media reveal" style="margin:0">
          <img loading="lazy" width="1280" height="853" src="assets/images/Proposal.jpeg" alt="A special moment together">
        </figure>
      </div>
    </div>
  </section>

  <!-- Bonus Tips -->
  <section id="tips" class="section" aria-labelledby="tips-title">
    <div class="container">
      <h2 id="tips-title">Bonus Tips</h2>
      <p class="accent">A few small things that make the trip smoother.</p>

      <div class="stay-grid">
        <div class="card reveal">
          <ul class="stay-list">
            <li><strong>Cash:</strong> cards are common, but a little cash is useful for small spots.</li>
            <li><strong>Plug:</strong> Malta uses the UK 3‑pin plug.</li>
            <li><strong>Timing:</strong> build in a buffer for airport + ferry connections.</li>
            <li><strong>Explore:</strong> schedule one “no plans” afternoon — Gozo is best when you wander.</li>
          </ul>
        </div>

        <figure class="media reveal" style="margin:0">
          <img loading="lazy" width="1280" height="853" src="assets/images/Victoria.jpeg" alt="Victoria, Gozo vibes">
        </figure>
      </div>
    </div>
  </section>
  <!-- Where to Stay -->
  <section id="stay" class="section" aria-labelledby="stay-title">
    <div class="container">
      <h2 id="stay-title">🌿 Where to Stay on Gozo</h2>
      <p class="accent">Short distances, big views — pick the vibe you want and everything is a quick drive away.</p>

      <div class="stay-grid">
        <div class="card reveal">
          <h3>Choose an area</h3>
          <div style="display:grid; gap:14px; margin-top:10px">
            <div class="card" style="padding:16px">
              <h4 style="margin:0 0 6px">Victoria (Rabat)</h4>
              <p style="margin:0">The island’s lively hub — cafés, shops, and the easiest base for getting around.</p>
            </div>
            <div class="card" style="padding:16px">
              <h4 style="margin:0 0 6px">Xlendi or Marsalforn</h4>
              <p style="margin:0">Seaside villages with promenades, swimming spots, and plenty of restaurants.</p>
            </div>
            <div class="card" style="padding:16px">
              <h4 style="margin:0 0 6px">Għarb / San Lawrenz</h4>
              <p style="margin:0">Quiet countryside, stone farmhouses, wide skies — perfect for a slower pace.</p>
            </div>
          </div>

          <h3 style="margin-top:14px">Accommodation style</h3>
          <ul class="stay-list">
            <li><strong>Boutique hotels:</strong> easy, service-led stays.</li>
            <li><strong>Farmhouses with pools:</strong> brilliant for groups and families.</li>
            <li><strong>Apartments:</strong> flexible, often with sea views.</li>
          </ul>
        </div>

        <div class="card reveal">
          <h3>Handy picks (ideas)</h3>
          <ul class="stay-list">
            <li><strong>Hotel Ta’ Ċenċ &amp; Spa:</strong> peaceful, elevated setting with spa facilities.</li>
            <li><strong>Kempinski Hotel San Lawrenz:</strong> resort-style comfort in the west of the island.</li>
            <li><strong>Boutique stays in Victoria:</strong> great if you want to walk to cafés and bars.</li>
            <li><strong>Farmhouses near Għarb:</strong> ideal for groups wanting a shared base.</li>
          </ul>
          <p style="margin-top:10px">If you tell us what vibe you want (quiet vs lively, hotel vs farmhouse), we’ll happily suggest a few options.</p>

          <figure class="media" style="margin-top:14px">
            <img loading="lazy" width="1280" height="853" src="assets/images/Canada.jpeg" alt="Gozo travel vibes">
          </figure>
        </div>
      </div>
    </div>
  </section>


    <!-- RSVP -->
  <section id="rsvp" class="section rsvp" aria-labelledby="rsvp-title">
    <div class="container">
      <h2 id="rsvp-title">RSVP</h2>
      <p class="accent">One quick form and you’re done.</p>

      <div class="card reveal" style="max-width:720px;margin:0 auto;text-align:center">
        <p style="margin:0 0 14px">Please RSVP via our Google Form so we can confirm numbers and meal choices.</p>
        <a class="btn" id="googleFormBtn" href="https://forms.gle/REPLACE_ME" target="_blank" rel="noopener">Open RSVP Form</a>
        <p style="margin:10px 0 0; font-size:.95rem; opacity:.9">If the link doesn’t work for you, message us and we’ll sort it.</p>
      </div>
    </div>
  </section>


  
  <!-- Footer -->
  <footer role="contentinfo">
    <div class="footer-motif" aria-hidden="true"></div>
    <div class="container footer-inner">
      <p style="text-align:center;margin:0;font-family:'Cormorant Garamond',serif;font-size:1.2rem">With love from Gozo · <span style="color:var(--gold)">☼</span> · See you on our island</p>
      <p style="text-align:center;margin:8px 0 0;font-size:.85rem;opacity:.8">Images: Dwejra Inland Sea; Mġarr Harbour; Ramla Bay; Xlendi Bay — via Wikimedia Commons.</p>
    </div>
  </footer>

  <!-- Waves audio element -->
  <audio id="waves" playsinline loop muted preload="auto"></audio>

  <div class="audio-toggle" role="region" aria-label="Audio controls">
    <span>Waves</span>
    <button id="audioBtn" type="button" aria-pressed="false" aria-controls="waves">Sound off</button>
  </div>

  <script>
(() => {
  const $ = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  // Reveal on scroll (keeps images/maps/cards visible once in view)
  const reveals = $$('.reveal');
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add('visible');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12 });
    reveals.forEach(el => io.observe(el));
  } else {
    reveals.forEach(el => el.classList.add('visible'));
  }

  // Countdown
  const elD = $('#d'), elH = $('#h'), elM = $('#m'), elS = $('#s');
  // Update this if needed:
  const WEDDING_ISO = '2026-09-10T14:00:00+02:00';
  const target = new Date(WEDDING_ISO).getTime();

  function pad(n){ return String(n).padStart(2,'0'); }

  function tick(){
    if (!elD || !elH || !elM || !elS) return;
    const now = Date.now();
    let diff = target - now;

    if (!Number.isFinite(diff)) {
      elD.textContent = elH.textContent = elM.textContent = elS.textContent = '—';
      return;
    }

    if (diff <= 0) {
      elD.textContent = '0';
      elH.textContent = '00';
      elM.textContent = '00';
      elS.textContent = '00';
      return;
    }

    const sec = Math.floor(diff / 1000);
    const days = Math.floor(sec / 86400);
    const hours = Math.floor((sec % 86400) / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    const secs = sec % 60;

    elD.textContent = String(days);
    elH.textContent = pad(hours);
    elM.textContent = pad(mins);
    elS.textContent = pad(secs);
  }
  tick();
  setInterval(tick, 1000);

  // Mobile waves audio (safe, non-blocking)
  const btn = $('#soundToggle');
  const audio = $('#wavesAudio');
  if (btn && audio) {
    let audible = false;

    function updateBtn() {
      btn.textContent = audible ? 'Sound on' : 'Sound off';
      btn.setAttribute('aria-pressed', audible ? 'true' : 'false');
    }
    updateBtn();

    async function enableSound(){
      if (audible) return;
      try {
        audio.muted = false;
        audio.volume = 0.35;
        await audio.play();
        audible = true;
        updateBtn();
      } catch {}
    }

    btn.addEventListener('click', async () => {
      if (!audible) return enableSound();
      if (!audio.paused) {
        audio.pause();
        audible = false;
        updateBtn();
      } else {
        await enableSound();
      }
    });

    ['pointerdown','touchstart','click','keydown']
      .forEach(ev => window.addEventListener(ev, enableSound, { once:true, passive:true }));
  }

  // Mobile gold fish: darts towards your tap, then bolts away LEFT (slower)
  const goldFishSVG = `
  <svg viewBox="0 0 160 96" aria-hidden="true">
    <defs>
      <linearGradient id="goldBody" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#E6B655"/><stop offset="100%" stop-color="#D6A248"/>
      </linearGradient>
    </defs>

    <g class="fish-wrap">
      <ellipse cx="78" cy="48" rx="46" ry="26" fill="url(#goldBody)"/>
      <g class="tail">
        <path d="M112 48 L152 72 Q145 48 152 24 Z" fill="#E6B655"/>
      </g>
      <path class="fin" d="M68 34 Q84 18 98 30 L84 40 Z" fill="#E6B655"/>
      <path class="fin" d="M68 62 Q84 78 98 66 L84 56 Z" fill="#E6B655"/>
      <circle cx="58" cy="44" r="6" fill="#fff"/><circle cx="59" cy="44" r="3" fill="#243133"/>
      <path d="M50 54 q8 6 16 0" stroke="#A75A32" stroke-width="3" fill="none" stroke-linecap="round"/>
    </g>
  </svg>`;

  let fishEl = null;
  let lastFishAt = 0;

  function isMobile(){
    return window.matchMedia('(max-width: 767.98px)').matches ||
           window.matchMedia('(pointer: coarse)').matches;
  }

  function ensureFish(){
    if (!fishEl){
      fishEl = document.createElement('div');
      fishEl.className = 'goldfish';
      fishEl.innerHTML = goldFishSVG;
      document.body.appendChild(fishEl);

      fishEl.addEventListener('animationend', (e) => {
        if (e.animationName === 'fish-fade'){
          fishEl.classList.remove('swimming');
          fishEl.style.opacity = '0';
        }
      });
    }
    return fishEl;
  }

  function shouldIgnoreTarget(target){
    return !!target?.closest?.('a, button, input, select, textarea, label');
  }

  function clamp(n, a, b){ return Math.max(a, Math.min(b, n)); }

  function launchFish(x, y){
    if (!isMobile()) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const now = performance.now();
    if (now - lastFishAt < 800) return; // anti-spam
    lastFishAt = now;

    const el = ensureFish();

    // Fish is smaller; centre around the tap
    const midX = x - 40;
    const midY = y - 28;

    // Start off-screen right so it "darts in" towards the tap
    const startX = window.innerWidth + 120;
    const startY = clamp(midY + (Math.random()*120 - 60), 20, window.innerHeight - 80);

    // Escape off-screen left with slight vertical drift
    const endX = -220;
    const endY = clamp(midY + (Math.random()*140 - 70), 20, window.innerHeight - 80);

    const dur = 2800 + Math.floor(Math.random() * 1600); // 2800–4400ms (slower)

    el.style.setProperty('--sx', `${startX}px`);
    el.style.setProperty('--sy', `${startY}px`);
    el.style.setProperty('--mx', `${midX}px`);
    el.style.setProperty('--my', `${midY}px`);
    el.style.setProperty('--ex', `${endX}px`);
    el.style.setProperty('--ey', `${endY}px`);
    el.style.setProperty('--dur', `${dur}ms`);
    el.style.setProperty('--flip', '-1'); // face left

    el.classList.remove('swimming');
    el.style.animation = 'none';
    void el.offsetWidth; // reflow
    el.style.animation = '';
    el.classList.add('swimming');
  }

  ['pointerdown','touchstart'].forEach(ev=>{
    window.addEventListener(ev, (e)=>{
      if (shouldIgnoreTarget(e.target)) return;
      const pt = e.touches ? e.touches[0] : e;
      launchFish(pt.clientX, pt.clientY);
    }, { passive:true });
  });

})();
</script>
</body>
</html>
