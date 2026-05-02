(() => {
  const state = {
    observer: null,
  };

  const caseStudies = [
    {
      title: 'Glow FM Digital Platform',
      type: 'Media Platform',
      problem: 'Radio brands need more than a basic website; they need a digital hub for live listening, news, shows, schedules, presenters, galleries, adverts, and audience growth.',
      solution: 'Built and maintained a scalable media website structure with content publishing, live stream access, show discovery, SEO pages, and digital growth-ready sections.',
      features: ['Live radio entry points', 'News and content publishing', 'Show and presenter pages', 'SEO and audience growth structure'],
      impact: 'Strengthened the station\'s digital presence and created a stronger foundation for online engagement, monetization, and brand visibility.',
      stack: ['Laravel', 'Livewire', 'Alpine.js', 'Tailwind CSS', 'SEO'],
      link: 'https://glowfmradio.com/',
      accent: '220, 38, 38',
    },
    {
      title: 'BootKode',
      type: 'EdTech Platform',
      problem: 'Aspiring developers need guided, practical learning paths with structured course materials, roadmaps, and certification flow.',
      solution: 'Designed an EdTech platform concept for course materials, videos, PDFs, audio lessons, learning roadmaps, and monetized certificates.',
      features: ['Course content structure', 'Career roadmaps', 'Certification flow', 'Student-focused learning experience'],
      impact: 'Positions the brand as a practical coding bootcamp platform for project-based learning and future developer mentorship.',
      stack: ['Laravel', 'Livewire', 'Tailwind CSS', 'MySQL', 'EdTech'],
      link: 'https://bootkode.laravel.cloud/',
      accent: '37, 99, 235',
    },
    {
      title: 'School Management System',
      type: 'Education System',
      problem: 'Schools often struggle with scattered records, manual results processing, payment tracking, communication, and role-based administration.',
      solution: 'Built a complete school website and management system with dashboards for administrative, academic, student, parent, and communication workflows.',
      features: ['Multi-role dashboards', 'Student records', 'Result processing', 'CBT/e-learning modules'],
      impact: 'Improved school administration by centralizing key workflows into a single web-based system.',
      stack: ['Laravel', 'MySQL', 'Dashboards', 'SchoolTech'],
      link: '#projects',
      accent: '124, 58, 237',
    },
    {
      title: 'MannaRise',
      type: 'Faith-Based Platform',
      problem: 'Faith communities need a clean and accessible way to publish daily devotionals, audio messages, and spiritual content online.',
      solution: 'Built a Laravel-powered devotional platform for daily devotionals, audio content, responsive reading, and SEO-ready public pages.',
      features: ['Daily devotional publishing', 'Audio devotional support', 'Responsive public pages', 'SEO-ready content structure'],
      impact: 'Shows ability to build focused content platforms for churches, ministries, NGOs, and faith-based communities.',
      stack: ['Laravel', 'MySQL', 'Audio Content', 'SEO'],
      link: 'https://mannarise.ct.ws/',
      accent: '22, 101, 52',
      image: './files/mannarise-preview.svg',
    },
  ];

  const serviceOptions = [
    'Schools and educational institutions',
    'Radio stations and media brands',
    'Churches, ministries, and NGOs',
    'Startups and small businesses',
    'Corporate teams that need workflow automation',
    'Founders who need product-minded web delivery',
  ];

  const waitForElement = (selector, callback, attempts = 40) => {
    const element = document.querySelector(selector);
    if (element) {
      callback(element);
      return;
    }

    if (attempts <= 0) return;
    window.setTimeout(() => waitForElement(selector, callback, attempts - 1), 150);
  };

  const revealElement = (element) => {
    element.setAttribute('data-reveal', 'up');

    if ('IntersectionObserver' in window) {
      if (!state.observer) {
        state.observer = new IntersectionObserver((entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              entry.target.classList.add('is-visible');
              state.observer.unobserve(entry.target);
            }
          });
        }, { threshold: 0.12 });
      }

      state.observer.observe(element);
    } else {
      element.classList.add('is-visible');
    }
  };

  const createProjectCard = (project) => {
    const card = document.createElement('article');
    card.dataset.project = project.title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    card.style.setProperty('--project-rgb', project.accent);
    card.className = 'project-card flex h-full flex-col rounded-2xl border border-stone-200 bg-white p-5 shadow-sm';

    const preview = project.image
      ? `<img src="${project.image}" alt="${project.title} project preview" class="project-preview-image" loading="lazy" />`
      : `<div class="project-preview-art"><div class="project-preview-grid"></div><div class="project-preview-shell"><div class="project-preview-dots"><span></span><span></span><span></span></div><div class="project-preview-panel project-preview-panel-one"></div><div class="project-preview-panel project-preview-panel-two"></div><div class="project-preview-panel project-preview-panel-three"></div></div></div>`;

    card.innerHTML = `
      <div class="project-preview mb-5">${preview}</div>
      <div class="flex flex-1 flex-col">
        <p class="mb-2 text-sm font-bold uppercase tracking-[0.18em]" style="color: rgb(${project.accent})">${project.type}</p>
        <h3 class="font-display text-xl font-semibold text-zinc-900">${project.title}</h3>
        <p class="mt-3 flex-1 text-sm leading-6 text-zinc-600">${project.solution}</p>
        <div class="project-stack mt-5">
          ${project.stack.map((item, index) => `<span class="project-stack-tag" style="--tag-delay: ${index * 80}ms">${item}</span>`).join('')}
        </div>
        <a href="${project.link}" ${project.link.startsWith('http') ? 'target="_blank" rel="noopener noreferrer"' : ''} class="project-link mt-6 text-sm font-bold" style="color: rgb(${project.accent})">
          ${project.link.startsWith('http') ? 'Visit Website' : 'View Project'} <span class="project-link-arrow">&rarr;</span>
        </a>
      </div>
    `;

    revealElement(card);
    return card;
  };

  const upsertMannaRiseCard = () => {
    waitForElement('#projects', (projectsSection) => {
      if (document.querySelector('[data-project="mannarise"]') || document.querySelector('[data-project="mannarise-"]')) return;

      const projectGrid = projectsSection.querySelector('.grid') || projectsSection.querySelector('[class*="grid"]');
      if (!projectGrid) return;

      const mannaRise = caseStudies.find((project) => project.title === 'MannaRise');
      projectGrid.appendChild(createProjectCard(mannaRise));
    });
  };

  const addFeaturedCaseStudies = () => {
    waitForElement('#projects', (projectsSection) => {
      if (document.querySelector('#featured-case-studies')) return;

      const section = document.createElement('section');
      section.id = 'featured-case-studies';
      section.className = 'mx-auto max-w-6xl px-4 py-16';
      section.innerHTML = `
        <div class="mb-8 max-w-3xl" data-reveal="up">
          <p class="mb-3 text-sm font-bold uppercase tracking-[0.2em] text-red-700">Selected Case Studies</p>
          <h2 class="font-display text-3xl font-bold text-zinc-950 md:text-4xl">Projects that show product thinking, not just page design.</h2>
          <p class="mt-4 text-base leading-7 text-zinc-600">A stronger look at the problem, solution, features, and value behind my most important platforms across media, education, EdTech, and faith-based content.</p>
        </div>
        <div class="grid gap-5 lg:grid-cols-2">
          ${caseStudies.map((project, index) => `
            <article class="rounded-2xl border border-stone-200 bg-white p-6 shadow-sm transition hover:-translate-y-1 hover:shadow-lg" style="--reveal-delay:${index * 90}ms" data-reveal="up">
              <div class="mb-4 flex flex-wrap items-center gap-3">
                <span class="rounded-full px-3 py-1 text-xs font-extrabold uppercase tracking-[0.14em]" style="background: rgba(${project.accent}, 0.1); color: rgb(${project.accent})">${project.type}</span>
                <span class="text-xs font-bold text-zinc-400">Case Study</span>
              </div>
              <h3 class="font-display text-2xl font-bold text-zinc-950">${project.title}</h3>
              <div class="mt-5 grid gap-4 text-sm leading-6 text-zinc-600 md:grid-cols-2">
                <div>
                  <p class="font-bold text-zinc-900">Problem</p>
                  <p class="mt-1">${project.problem}</p>
                </div>
                <div>
                  <p class="font-bold text-zinc-900">Solution</p>
                  <p class="mt-1">${project.solution}</p>
                </div>
              </div>
              <div class="mt-5">
                <p class="font-bold text-zinc-900">Key Features</p>
                <div class="mt-3 flex flex-wrap gap-2">
                  ${project.features.map((feature) => `<span class="rounded-full border border-stone-200 bg-stone-50 px-3 py-1 text-xs font-bold text-zinc-700">${feature}</span>`).join('')}
                </div>
              </div>
              <p class="mt-5 rounded-2xl border border-stone-200 bg-stone-50 p-4 text-sm leading-6 text-zinc-700"><strong class="text-zinc-950">Impact:</strong> ${project.impact}</p>
              <div class="mt-5 flex flex-wrap gap-2">
                ${project.stack.map((item) => `<span class="rounded-full px-3 py-1 text-xs font-bold" style="background: rgba(${project.accent}, 0.08); color: rgb(${project.accent})">${item}</span>`).join('')}
              </div>
              <a href="${project.link}" ${project.link.startsWith('http') ? 'target="_blank" rel="noopener noreferrer"' : ''} class="motion-button mt-6 inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-bold" style="border-color: rgba(${project.accent}, 0.28); color: rgb(${project.accent})">
                ${project.link.startsWith('http') ? 'Open Live Project' : 'View in Portfolio'} <span aria-hidden="true">&rarr;</span>
              </a>
            </article>
          `).join('')}
        </div>
      `;

      projectsSection.parentNode.insertBefore(section, projectsSection);
      section.querySelectorAll('[data-reveal]').forEach(revealElement);
    });
  };

  const enhanceHireMeSection = () => {
    const contactSection = document.querySelector('#contact');
    if (!contactSection || document.querySelector('#client-fit-section')) return;

    const section = document.createElement('section');
    section.id = 'client-fit-section';
    section.className = 'mx-auto max-w-6xl px-4 py-14';
    section.innerHTML = `
      <div class="rounded-3xl border border-stone-200 bg-white p-6 shadow-sm md:p-8" data-reveal="up">
        <div class="grid gap-8 lg:grid-cols-[1fr,0.9fr] lg:items-center">
          <div>
            <p class="mb-3 text-sm font-bold uppercase tracking-[0.2em] text-red-700">Who I Can Help</p>
            <h2 class="font-display text-3xl font-bold text-zinc-950 md:text-4xl">I build web platforms that solve real workflow, content, and growth problems.</h2>
            <p class="mt-4 text-base leading-7 text-zinc-600">I help schools, media brands, churches, NGOs, startups, and businesses build scalable web platforms, improve their digital presence, and automate operations with Laravel, React, Vue, Livewire, and Tailwind CSS.</p>
            <div class="mt-6 flex flex-wrap gap-3">
              <a href="#contact" class="motion-button rounded-full bg-red-600 px-5 py-3 text-sm font-bold text-white hover:bg-red-700">Discuss a Project</a>
              <a href="./files/Oyetoke_Adedayo_CV.pdf" target="_blank" rel="noopener noreferrer" class="motion-button rounded-full border border-stone-300 px-5 py-3 text-sm font-bold text-zinc-800 hover:border-red-300 hover:text-red-700">View CV</a>
            </div>
          </div>
          <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
            ${serviceOptions.map((item) => `<div class="rounded-2xl border border-stone-200 bg-stone-50 p-4 text-sm font-bold text-zinc-700">${item}</div>`).join('')}
          </div>
        </div>
      </div>
    `;

    contactSection.parentNode.insertBefore(section, contactSection);
    section.querySelectorAll('[data-reveal]').forEach(revealElement);
  };

  const addProjectCategorySummary = () => {
    waitForElement('#projects', (projectsSection) => {
      if (document.querySelector('#project-category-summary')) return;

      const summary = document.createElement('div');
      summary.id = 'project-category-summary';
      summary.className = 'mx-auto mb-10 grid max-w-6xl gap-3 px-4 sm:grid-cols-2 lg:grid-cols-3';
      summary.innerHTML = [
        ['Media Platform', 'Radio, news, shows, schedules, presenters'],
        ['EdTech', 'Courses, roadmaps, lessons, certification'],
        ['School Systems', 'Records, results, dashboards, e-learning'],
        ['Faith-Based Platforms', 'Devotionals, audio, content publishing'],
        ['Business Websites', 'SEO, brand presence, lead generation'],
        ['Automation', 'Admin workflows and digital operations'],
      ].map(([title, text], index) => `
        <div class="rounded-2xl border border-stone-200 bg-white p-4 shadow-sm" data-reveal="up" style="--reveal-delay:${index * 60}ms">
          <p class="font-display text-base font-bold text-zinc-950">${title}</p>
          <p class="mt-1 text-sm text-zinc-600">${text}</p>
        </div>
      `).join('');

      projectsSection.parentNode.insertBefore(summary, projectsSection);
      summary.querySelectorAll('[data-reveal]').forEach(revealElement);
    });
  };

  const init = () => {
    upsertMannaRiseCard();
    addFeaturedCaseStudies();
    addProjectCategorySummary();
    enhanceHireMeSection();
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
