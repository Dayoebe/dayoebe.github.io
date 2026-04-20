(() => {
  const LANGUAGE_STORAGE_KEY = 'wireless-terminal-language-v1';
  const SUPPORTED_LANGUAGES = {
    en: { label: 'English', dir: 'ltr', locale: 'en_NG' },
    es: { label: 'Español', dir: 'ltr', locale: 'es_ES' },
    fr: { label: 'Français', dir: 'ltr', locale: 'fr_FR' },
    ar: { label: 'العربية', dir: 'rtl', locale: 'ar_AR' },
    sw: { label: 'Kiswahili', dir: 'ltr', locale: 'sw_KE' },
    hi: { label: 'हिन्दी', dir: 'ltr', locale: 'hi_IN' },
    pt: { label: 'Português', dir: 'ltr', locale: 'pt_PT' }
  };

  const META = {
    en: {
      title: 'Adedayo Ebenezer Oyetoke | Full-Stack Web Developer',
      description: 'Adedayo Ebenezer Oyetoke is a Full-Stack Web Developer and EdTech specialist building scalable Laravel, Vue, and React applications for schools, media, banking, and corporate teams.',
      ogDescription: 'Portfolio of Adedayo Ebenezer Oyetoke, Full-Stack Web Developer focused on Laravel, Vue.js, React, EdTech, and digital growth.',
      twitterDescription: 'Portfolio of Adedayo Ebenezer Oyetoke, Full-Stack Web Developer focused on scalable web systems and digital product growth.',
      imageAlt: 'Adedayo Ebenezer Oyetoke, Full-Stack Web Developer'
    },
    es: {
      title: 'Adedayo Ebenezer Oyetoke | Desarrollador Web Full-Stack',
      description: 'Adedayo Ebenezer Oyetoke es desarrollador web full-stack y especialista en EdTech que crea aplicaciones escalables con Laravel, Vue y React para escuelas, medios, banca y equipos corporativos.',
      ogDescription: 'Portafolio de Adedayo Ebenezer Oyetoke, desarrollador web full-stack enfocado en Laravel, Vue.js, React, EdTech y crecimiento digital.',
      twitterDescription: 'Portafolio de Adedayo Ebenezer Oyetoke, desarrollador web full-stack enfocado en sistemas web escalables y crecimiento de productos digitales.',
      imageAlt: 'Adedayo Ebenezer Oyetoke, desarrollador web full-stack'
    },
    fr: {
      title: 'Adedayo Ebenezer Oyetoke | Développeur Web Full-Stack',
      description: 'Adedayo Ebenezer Oyetoke est développeur web full-stack et spécialiste EdTech, créant des applications Laravel, Vue et React évolutives pour les écoles, les médias, la banque et les équipes d’entreprise.',
      ogDescription: 'Portfolio d’Adedayo Ebenezer Oyetoke, développeur web full-stack axé sur Laravel, Vue.js, React, l’EdTech et la croissance digitale.',
      twitterDescription: 'Portfolio d’Adedayo Ebenezer Oyetoke, développeur web full-stack axé sur les systèmes web évolutifs et la croissance des produits numériques.',
      imageAlt: 'Adedayo Ebenezer Oyetoke, développeur web full-stack'
    },
    ar: {
      title: 'أديدايو إبنيزر أويتوك | مطور ويب Full-Stack',
      description: 'أديدايو إبنيزر أويتوك مطور ويب Full-Stack ومتخصص في تقنيات التعليم، يبني تطبيقات Laravel وVue وReact قابلة للتوسع للمدارس والإعلام والبنوك وفرق الشركات.',
      ogDescription: 'ملف أعمال أديدايو إبنيزر أويتوك، مطور ويب Full-Stack يركز على Laravel وVue.js وReact وتقنيات التعليم والنمو الرقمي.',
      twitterDescription: 'ملف أعمال أديدايو إبنيزر أويتوك، مطور ويب Full-Stack يركز على أنظمة ويب قابلة للتوسع ونمو المنتجات الرقمية.',
      imageAlt: 'أديدايو إبنيزر أويتوك، مطور ويب Full-Stack'
    },
    sw: {
      title: 'Adedayo Ebenezer Oyetoke | Msanidi wa Wavuti Full-Stack',
      description: 'Adedayo Ebenezer Oyetoke ni msanidi wa wavuti full-stack na mtaalamu wa EdTech anayejenga programu za Laravel, Vue na React zinazokua kwa shule, vyombo vya habari, benki na timu za kampuni.',
      ogDescription: 'Portifolio ya Adedayo Ebenezer Oyetoke, msanidi wa wavuti full-stack anayelenga Laravel, Vue.js, React, EdTech na ukuaji wa kidijitali.',
      twitterDescription: 'Portifolio ya Adedayo Ebenezer Oyetoke, msanidi wa wavuti full-stack anayelenga mifumo ya wavuti inayokua na ukuaji wa bidhaa za kidijitali.',
      imageAlt: 'Adedayo Ebenezer Oyetoke, msanidi wa wavuti full-stack'
    },
    hi: {
      title: 'Adedayo Ebenezer Oyetoke | फुल-स्टैक वेब डेवलपर',
      description: 'Adedayo Ebenezer Oyetoke एक फुल-स्टैक वेब डेवलपर और EdTech विशेषज्ञ हैं, जो स्कूलों, मीडिया, बैंकिंग और कॉर्पोरेट टीमों के लिए Laravel, Vue और React पर स्केलेबल एप्लिकेशन बनाते हैं।',
      ogDescription: 'Adedayo Ebenezer Oyetoke का पोर्टफोलियो, Laravel, Vue.js, React, EdTech और डिजिटल ग्रोथ पर केंद्रित फुल-स्टैक वेब डेवलपर।',
      twitterDescription: 'Adedayo Ebenezer Oyetoke का पोर्टफोलियो, स्केलेबल वेब सिस्टम और डिजिटल प्रोडक्ट ग्रोथ पर केंद्रित फुल-स्टैक वेब डेवलपर।',
      imageAlt: 'Adedayo Ebenezer Oyetoke, फुल-स्टैक वेब डेवलपर'
    },
    pt: {
      title: 'Adedayo Ebenezer Oyetoke | Desenvolvedor Web Full-Stack',
      description: 'Adedayo Ebenezer Oyetoke é desenvolvedor web full-stack e especialista em EdTech, criando aplicações escaláveis com Laravel, Vue e React para escolas, mídia, bancos e equipes corporativas.',
      ogDescription: 'Portfólio de Adedayo Ebenezer Oyetoke, desenvolvedor web full-stack focado em Laravel, Vue.js, React, EdTech e crescimento digital.',
      twitterDescription: 'Portfólio de Adedayo Ebenezer Oyetoke, desenvolvedor web full-stack focado em sistemas web escaláveis e crescimento de produtos digitais.',
      imageAlt: 'Adedayo Ebenezer Oyetoke, desenvolvedor web full-stack'
    }
  };

  const TRANSLATIONS = {
    es: {
      "Wireless Terminal": "Wireless Terminal",
      "Menu": "Menú",
      "Toggle menu": "Alternar menú",
      "Home": "Inicio",
      "About": "Acerca de",
      "Skills": "Habilidades",
      "Experience": "Experiencia",
      "Projects": "Proyectos",
      "Contact": "Contacto",
      "Language": "Idioma",
      "Full-Stack Web Developer | EdTech and Digital Growth": "Desarrollador Web Full-Stack | EdTech y Crecimiento Digital",
      "Full-Stack Web Developer": "Desarrollador Web Full-Stack",
      "I build and maintain scalable, user-centric applications for schools, media, and corporate teams. My stack includes Laravel, Vue.js, React, and Tailwind CSS, backed by practical product delivery and digital growth strategy.": "Construyo y mantengo aplicaciones escalables centradas en el usuario para escuelas, medios y equipos corporativos. Mi stack incluye Laravel, Vue.js, React y Tailwind CSS, con experiencia práctica en entrega de productos y estrategia de crecimiento digital.",
      "Hire Me": "Contrátame",
      "View Projects": "Ver proyectos",
      "20+ Projects": "Más de 20 proyectos",
      "Enterprise and client delivery": "Entregas empresariales y para clientes",
      "30% Faster": "30% más rápido",
      "Reduced project timelines": "Reducción de tiempos de proyecto",
      "100% Deadlines": "100% de plazos cumplidos",
      "Consistent client delivery": "Entrega constante para clientes",
      "2026-Present": "2026 - Actualidad",
      "Digital and Web Specialist, Glow FM": "Especialista digital y web, Glow FM",
      "Available for collaboration": "Disponible para colaboración",
      "Portrait of Adedayo Ebenezer Oyetoke": "Retrato de Adedayo Ebenezer Oyetoke",
      "Full-Stack Developer and Tech Educator": "Desarrollador Full-Stack y educador tecnológico",
      "Web": "Web",
      "Growth": "Crecimiento",
      "Location": "Ubicación",
      "Akure, Nigeria": "Akure, Nigeria",
      "Current Role": "Rol actual",
      "Founder, Wireless": "Fundador, Wireless",
      "Professional Summary": "Resumen profesional",
      "Full-Stack Web Developer and Digital and EdTech Specialist with hands-on expertise in Laravel, Vue.js, React, and Tailwind CSS. I build and maintain websites, manage digital growth, and deliver scalable applications for schools, media, and business clients.": "Desarrollador web full-stack y especialista digital y EdTech con experiencia práctica en Laravel, Vue.js, React y Tailwind CSS. Construyo y mantengo sitios web, gestiono crecimiento digital y entrego aplicaciones escalables para escuelas, medios y clientes empresariales.",
      "I am also the founder of BootKode, a tech-education platform focused on project-based learning for aspiring developers. I am passionate about AI, cloud technologies, mentorship, and measurable product outcomes.": "También soy fundador de BootKode, una plataforma de educación tecnológica centrada en aprendizaje basado en proyectos para futuros desarrolladores. Me apasionan la IA, las tecnologías cloud, la mentoría y los resultados medibles de producto.",
      "Contact Snapshot": "Datos de contacto",
      "Address": "Dirección",
      "Address:": "Dirección:",
      "Email": "Correo electrónico",
      "Email:": "Correo electrónico:",
      "Phone": "Teléfono",
      "Phone:": "Teléfono:",
      "Website": "Sitio web",
      "Website:": "Sitio web:",
      "GitHub / LinkedIn": "GitHub / LinkedIn",
      "Core Technical Skills": "Habilidades técnicas principales",
      "Practical stack for full lifecycle product delivery across web and EdTech systems.": "Stack práctico para entregar productos durante todo su ciclo de vida en sistemas web y EdTech.",
      "Frontend": "Frontend",
      "Backend": "Backend",
      "Mobile and Data": "Móvil y datos",
      "Tools and Design": "Herramientas y diseño",
      "Frontend Delivery": "Entrega frontend",
      "Backend Delivery": "Entrega backend",
      "Digital Growth Strategy": "Estrategia de crecimiento digital",
      "Problem Solving": "Resolución de problemas",
      "Professional Experience": "Experiencia profesional",
      "Full SDLC delivery across web engineering, education technology, and digital media operations.": "Entrega completa del ciclo de vida del software en ingeniería web, tecnología educativa y operaciones de medios digitales.",
      "2022 - Present": "2022 - Actualidad",
      "Founder and Lead Developer, Wireless Computer Services": "Fundador y desarrollador líder, Wireless Computer Services",
      "Designed and deployed 20+ enterprise-grade applications for school, banking, corporate, and government clients.": "Diseñé y desplegué más de 20 aplicaciones empresariales para clientes escolares, bancarios, corporativos y gubernamentales.",
      "Reduced project timelines by 30% through Laravel backend and Vue plus Tailwind integration.": "Reduje los tiempos de proyecto en 30% mediante backend Laravel e integración de Vue con Tailwind.",
      "Led end-to-end SDLC: requirements, architecture, implementation, deployment, and maintenance.": "Lideré el ciclo completo: requisitos, arquitectura, implementación, despliegue y mantenimiento.",
      "January 2026 - Present": "Enero de 2026 - Actualidad",
      "Digital and Web Specialist, Glow 99.1 FM (Akure)": "Especialista digital y web, Glow 99.1 FM (Akure)",
      "Built and maintain the station website: www.glowfmradio.com.": "Construí y mantengo el sitio web de la emisora: www.glowfmradio.com.",
      "Manage social media growth, audience engagement, and monetization campaigns.": "Gestiono el crecimiento en redes sociales, la interacción con la audiencia y campañas de monetización.",
      "Execute digital strategy and analytics optimization aligned with station objectives.": "Ejecuto estrategia digital y optimización analítica alineadas con los objetivos de la emisora.",
      "2025 | Anambra State": "2025 | Estado de Anambra",
      "NYSC Teacher and Developer, Elites International College": "Profesor NYSC y desarrollador, Elites International College",
      "Taught Senior Secondary Mathematics and Physics using structured, problem-solving methods.": "Enseñé Matemáticas y Física de secundaria superior con métodos estructurados de resolución de problemas.",
      "Built school website and full management system from scratch with multi-role dashboards.": "Construí desde cero el sitio web y un sistema completo de gestión escolar con paneles multirol.",
      "Implemented records, result processing, payments, CBT, e-learning, and announcement modules.": "Implementé módulos de registros, procesamiento de resultados, pagos, CBT, e-learning y anuncios.",
      "Freelance and Earlier Roles": "Freelance y roles anteriores",
      "Freelance Web Developer and Consultant: built school, portfolio, e-commerce, and business sites.": "Desarrollador web freelance y consultor: creé sitios escolares, portafolios, e-commerce y sitios empresariales.",
      "Media Coordinator, First Baptist Church: led live streaming and digital outreach operations.": "Coordinador de medios, First Baptist Church: lideré transmisiones en vivo y operaciones de difusión digital.",
      "Intern and Computer Apprentice, Zacest Computer Center: foundation in office tools, graphics, and animation.": "Pasante y aprendiz de computación, Zacest Computer Center: base en herramientas de oficina, gráficos y animación.",
      "Education": "Educación",
      "B.Tech, Industrial Mathematics (2018 - 2024)": "B.Tech, Matemáticas Industriales (2018 - 2024)",
      "Key Achievements": "Logros clave",
      "Delivered over 20 client projects with strong quality outcomes.": "Entregué más de 20 proyectos para clientes con sólidos resultados de calidad.",
      "Met 100% of project deadlines through effective planning and communication.": "Cumplí el 100% de los plazos mediante planificación y comunicación efectivas.",
      "Improved engagement by optimizing website performance and UX structure.": "Mejoré la interacción optimizando el rendimiento web y la estructura UX.",
      "Leadership and Interests": "Liderazgo e intereses",
      "Open-source contributor, tech mentor, and workshop facilitator.": "Colaborador open-source, mentor tecnológico y facilitador de talleres.",
      "Languages: English (Fluent), Yoruba (Native), Pidgin (Conversational).": "Idiomas: inglés (fluido), yoruba (nativo), pidgin (conversacional).",
      "Interests: AI applications, cloud technology, digital art, and web/mobile trend blogging.": "Intereses: aplicaciones de IA, tecnología cloud, arte digital y blogs sobre tendencias web/móvil.",
      "Projects and Portfolio": "Proyectos y portafolio",
      "Production platforms across media, education, banking, and developer education.": "Plataformas en producción para medios, educación, banca y formación de desarrolladores.",
      "Media Website": "Sitio web de medios",
      "School Website": "Sitio web escolar",
      "Bank Website": "Sitio web bancario",
      "Banking Platform": "Plataforma bancaria",
      "EdTech Platform": "Plataforma EdTech",
      "Blog and Portfolio": "Blog y portafolio",
      "Client Websites": "Sitios de clientes",
      "Corporate and Portfolio Systems": "Sistemas corporativos y de portafolio",
      "Multiple client sectors": "Múltiples sectores de clientes",
      "Built, maintain, and update station website while integrating growth-focused digital operations.": "Construyo, mantengo y actualizo el sitio de la emisora integrando operaciones digitales orientadas al crecimiento.",
      "Developed website and management suite with records, result uploads, report cards, and dashboards.": "Desarrollé sitio web y suite de gestión con registros, carga de resultados, boletines y paneles.",
      "Secure, responsive banking web experience focused on trust and discoverability.": "Experiencia web bancaria segura y responsive, enfocada en confianza y visibilidad.",
      "Learning platform with videos, PDFs, audio lessons, career roadmaps, and certification flow.": "Plataforma de aprendizaje con videos, PDFs, lecciones de audio, rutas profesionales y flujo de certificación.",
      "Personal blog and portfolio system with admin dashboard and SEO-focused content architecture.": "Sistema personal de blog y portafolio con panel administrativo y arquitectura de contenido enfocada en SEO.",
      "SEO-optimized business and portfolio websites that improve online visibility and engagement.": "Sitios empresariales y de portafolio optimizados para SEO que mejoran visibilidad e interacción.",
      "Visit Website": "Visitar sitio",
      "What Clients Say": "Lo que dicen los clientes",
      "Trusted by schools, media brands, and businesses for reliable delivery and clear communication.": "Confianza de escuelas, marcas de medios y empresas por entregas fiables y comunicación clara.",
      "All": "Todo",
      "Media": "Medios",
      "Finance": "Finanzas",
      "Corporate": "Corporativo",
      "Book a Call": "Reserva una llamada",
      "Let's Discuss Your Project": "Hablemos de tu proyecto",
      "Book a 20-minute discovery call to review your goals, timeline, and best technical approach for your website or platform.": "Reserva una llamada de descubrimiento de 20 minutos para revisar tus objetivos, plazos y el mejor enfoque técnico para tu sitio o plataforma.",
      "Book a Call on Calendly": "Reservar en Calendly",
      "Chat on WhatsApp": "Chatear por WhatsApp",
      "Frequently Asked Questions": "Preguntas frecuentes",
      "Quick answers to common questions about process, delivery, and collaboration.": "Respuestas rápidas a preguntas comunes sobre proceso, entrega y colaboración.",
      "Process": "Proceso",
      "Technical": "Técnico",
      "Support": "Soporte",
      "Search question...": "Buscar pregunta...",
      "No FAQ matched your search. Try another keyword.": "Ninguna pregunta coincide con tu búsqueda. Prueba otra palabra clave.",
      "Get In Touch": "Ponte en contacto",
      "I am open to full-time roles, contract projects, and strategic collaborations in software engineering, digital product delivery, and EdTech platforms.": "Estoy disponible para roles de tiempo completo, proyectos por contrato y colaboraciones estratégicas en ingeniería de software, entrega de productos digitales y plataformas EdTech.",
      "Social Media": "Redes sociales",
      "Send a Message": "Enviar mensaje",
      "Name": "Nombre",
      "Subject": "Asunto",
      "Message": "Mensaje",
      "Send Message": "Enviar mensaje",
      "New Portfolio Contact Message": "Nuevo mensaje de contacto del portafolio",
      "Copyright": "Derechos de autor",
      "What kind of projects do you handle?": "¿Qué tipo de proyectos manejas?",
      "I build and maintain websites, web applications, school systems, and digital platforms for media, education, banking, and business clients.": "Construyo y mantengo sitios web, aplicaciones web, sistemas escolares y plataformas digitales para clientes de medios, educación, banca y negocios.",
      "How long does a typical project take?": "¿Cuánto dura un proyecto típico?",
      "Small websites usually take 1 to 3 weeks. Larger platforms can take 4 to 12 weeks depending on features, content readiness, and approvals.": "Los sitios pequeños suelen tomar de 1 a 3 semanas. Las plataformas más grandes pueden tomar de 4 a 12 semanas según funciones, contenido y aprobaciones.",
      "Do you work on existing websites?": "¿Trabajas en sitios existentes?",
      "Yes. I redesign, optimize performance, fix bugs, add features, and improve SEO for existing websites and applications.": "Sí. Rediseño, optimizo rendimiento, corrijo errores, agrego funciones y mejoro SEO en sitios y aplicaciones existentes.",
      "What technologies do you use?": "¿Qué tecnologías usas?",
      "My core stack includes Laravel, Vue.js, React, Tailwind CSS, Livewire, MySQL, and Alpine.js.": "Mi stack principal incluye Laravel, Vue.js, React, Tailwind CSS, Livewire, MySQL y Alpine.js.",
      "Do you provide maintenance after launch?": "¿Ofreces mantenimiento después del lanzamiento?",
      "Yes. I provide post-launch support, updates, backups, and technical maintenance packages.": "Sí. Ofrezco soporte posterior al lanzamiento, actualizaciones, copias de seguridad y paquetes de mantenimiento técnico.",
      "How do we start working together?": "¿Cómo empezamos a trabajar juntos?",
      "Book a discovery call on Calendly or send a message through the contact form. I will review your needs and share scope, timeline, and cost.": "Reserva una llamada en Calendly o envía un mensaje por el formulario de contacto. Revisaré tus necesidades y compartiré alcance, plazo y costo.",
      "\"Adedayo rebuilt our station website and helped us run a stronger digital strategy. Our online engagement and brand visibility improved noticeably.\"": "\"Adedayo reconstruyó el sitio de nuestra emisora y nos ayudó a ejecutar una estrategia digital más sólida. Nuestra interacción online y visibilidad de marca mejoraron notablemente.\"",
      "\"He delivered both our school website and management system with features that made administration easier for staff and parents.\"": "\"Entregó nuestro sitio escolar y sistema de gestión con funciones que facilitaron la administración para el personal y los padres.\"",
      "\"From planning to deployment, the process was professional. The final website reflects our institution and works smoothly across devices.\"": "\"Desde la planificación hasta el despliegue, el proceso fue profesional. El sitio final refleja nuestra institución y funciona bien en todos los dispositivos.\"",
      "\"Communication was clear, timelines were respected, and every revision was handled quickly.\"": "\"La comunicación fue clara, los plazos se respetaron y cada revisión se atendió rápidamente.\"",
      "\"Our new platform feels modern, fast, and easy to manage. We have seen better user response since launch.\"": "\"Nuestra nueva plataforma se siente moderna, rápida y fácil de gestionar. Hemos visto mejor respuesta de usuarios desde el lanzamiento.\"",
      "\"Adedayo combines technical depth with business understanding. He does not just build pages, he solves real workflow problems.\"": "\"Adedayo combina profundidad técnica con comprensión del negocio. No solo crea páginas, resuelve problemas reales de flujo de trabajo.\"",
      "Management": "Dirección",
      "Academic Office": "Oficina académica",
      "Admin Lead": "Líder administrativo",
      "Operations Unit": "Unidad de operaciones",
      "Operations Team": "Equipo de operaciones",
      "Client (NDA)": "Cliente (NDA)",
      "Founder": "Fundador",
      "Product Lead": "Líder de producto",
      "Director": "Director",
      "SME Corporate Website": "Sitio corporativo PYME",
      "Business Platform Project": "Proyecto de plataforma empresarial",
      "Enterprise Web Project": "Proyecto web empresarial",
      "Saved message draft restored on this device.": "Borrador de mensaje restaurado en este dispositivo.",
      "Connection restored. Fresh content is available again.": "Conexión restaurada. El contenido actualizado vuelve a estar disponible.",
      "You are offline. Cached pages and saved message drafts are still available.": "Estás sin conexión. Las páginas en caché y borradores guardados siguen disponibles.",
      "You are offline. Your draft is saved on this device and can be sent when you reconnect.": "Estás sin conexión. Tu borrador se guardó en este dispositivo y podrá enviarse al reconectar.",
      "Thanks. Your message was submitted successfully.": "Gracias. Tu mensaje se envió correctamente."
    },
    fr: {
      "Menu": "Menu",
      "Toggle menu": "Basculer le menu",
      "Home": "Accueil",
      "About": "À propos",
      "Skills": "Compétences",
      "Experience": "Expérience",
      "Projects": "Projets",
      "Contact": "Contact",
      "Language": "Langue",
      "Full-Stack Web Developer | EdTech and Digital Growth": "Développeur Web Full-Stack | EdTech et Croissance Digitale",
      "Full-Stack Web Developer": "Développeur Web Full-Stack",
      "I build and maintain scalable, user-centric applications for schools, media, and corporate teams. My stack includes Laravel, Vue.js, React, and Tailwind CSS, backed by practical product delivery and digital growth strategy.": "Je conçois et maintiens des applications évolutives centrées sur l’utilisateur pour les écoles, les médias et les équipes d’entreprise. Mon stack comprend Laravel, Vue.js, React et Tailwind CSS, avec une solide expérience en livraison produit et stratégie de croissance digitale.",
      "Hire Me": "Me recruter",
      "View Projects": "Voir les projets",
      "20+ Projects": "Plus de 20 projets",
      "Enterprise and client delivery": "Livraison entreprise et client",
      "30% Faster": "30 % plus rapide",
      "Reduced project timelines": "Délais de projet réduits",
      "100% Deadlines": "100 % des délais respectés",
      "Consistent client delivery": "Livraison client constante",
      "2026-Present": "2026 - Aujourd’hui",
      "Digital and Web Specialist, Glow FM": "Spécialiste digital et web, Glow FM",
      "Available for collaboration": "Disponible pour collaboration",
      "Portrait of Adedayo Ebenezer Oyetoke": "Portrait d’Adedayo Ebenezer Oyetoke",
      "Full-Stack Developer and Tech Educator": "Développeur Full-Stack et formateur tech",
      "Growth": "Croissance",
      "Location": "Localisation",
      "Current Role": "Rôle actuel",
      "Founder, Wireless": "Fondateur, Wireless",
      "Professional Summary": "Résumé professionnel",
      "Full-Stack Web Developer and Digital and EdTech Specialist with hands-on expertise in Laravel, Vue.js, React, and Tailwind CSS. I build and maintain websites, manage digital growth, and deliver scalable applications for schools, media, and business clients.": "Développeur web full-stack et spécialiste digital et EdTech avec une expérience pratique de Laravel, Vue.js, React et Tailwind CSS. Je crée et maintiens des sites web, pilote la croissance digitale et livre des applications évolutives pour les écoles, les médias et les entreprises.",
      "I am also the founder of BootKode, a tech-education platform focused on project-based learning for aspiring developers. I am passionate about AI, cloud technologies, mentorship, and measurable product outcomes.": "Je suis également fondateur de BootKode, une plateforme d’éducation tech axée sur l’apprentissage par projet pour les développeurs en devenir. Je suis passionné par l’IA, le cloud, le mentorat et les résultats produit mesurables.",
      "Contact Snapshot": "Aperçu du contact",
      "Address": "Adresse",
      "Address:": "Adresse :",
      "Email": "E-mail",
      "Email:": "E-mail :",
      "Phone": "Téléphone",
      "Phone:": "Téléphone :",
      "Website": "Site web",
      "Website:": "Site web :",
      "Core Technical Skills": "Compétences techniques clés",
      "Practical stack for full lifecycle product delivery across web and EdTech systems.": "Stack pratique pour livrer des produits sur tout leur cycle de vie dans les systèmes web et EdTech.",
      "Frontend": "Frontend",
      "Backend": "Backend",
      "Mobile and Data": "Mobile et données",
      "Tools and Design": "Outils et design",
      "Frontend Delivery": "Livraison frontend",
      "Backend Delivery": "Livraison backend",
      "Digital Growth Strategy": "Stratégie de croissance digitale",
      "Problem Solving": "Résolution de problèmes",
      "Professional Experience": "Expérience professionnelle",
      "Full SDLC delivery across web engineering, education technology, and digital media operations.": "Livraison complète du cycle logiciel en ingénierie web, technologies éducatives et opérations médias digitales.",
      "2022 - Present": "2022 - Aujourd’hui",
      "Founder and Lead Developer, Wireless Computer Services": "Fondateur et développeur principal, Wireless Computer Services",
      "Designed and deployed 20+ enterprise-grade applications for school, banking, corporate, and government clients.": "Conception et déploiement de plus de 20 applications professionnelles pour des clients scolaires, bancaires, corporatifs et gouvernementaux.",
      "Reduced project timelines by 30% through Laravel backend and Vue plus Tailwind integration.": "Réduction des délais de projet de 30 % grâce à un backend Laravel et à l’intégration de Vue avec Tailwind.",
      "Led end-to-end SDLC: requirements, architecture, implementation, deployment, and maintenance.": "Pilotage complet du cycle logiciel : besoins, architecture, implémentation, déploiement et maintenance.",
      "January 2026 - Present": "Janvier 2026 - Aujourd’hui",
      "Digital and Web Specialist, Glow 99.1 FM (Akure)": "Spécialiste digital et web, Glow 99.1 FM (Akure)",
      "Built and maintain the station website: www.glowfmradio.com.": "Création et maintenance du site de la station : www.glowfmradio.com.",
      "Manage social media growth, audience engagement, and monetization campaigns.": "Gestion de la croissance sur les réseaux sociaux, de l’engagement de l’audience et des campagnes de monétisation.",
      "Execute digital strategy and analytics optimization aligned with station objectives.": "Exécution de la stratégie digitale et optimisation analytique alignées sur les objectifs de la station.",
      "2025 | Anambra State": "2025 | État d’Anambra",
      "NYSC Teacher and Developer, Elites International College": "Enseignant NYSC et développeur, Elites International College",
      "Taught Senior Secondary Mathematics and Physics using structured, problem-solving methods.": "Enseignement des mathématiques et de la physique au secondaire supérieur avec des méthodes structurées de résolution de problèmes.",
      "Built school website and full management system from scratch with multi-role dashboards.": "Création complète du site scolaire et d’un système de gestion avec tableaux de bord multi-rôles.",
      "Implemented records, result processing, payments, CBT, e-learning, and announcement modules.": "Implémentation des dossiers, résultats, paiements, CBT, e-learning et annonces.",
      "Freelance and Earlier Roles": "Freelance et rôles précédents",
      "Freelance Web Developer and Consultant: built school, portfolio, e-commerce, and business sites.": "Développeur web freelance et consultant : sites scolaires, portfolios, e-commerce et sites d’entreprise.",
      "Media Coordinator, First Baptist Church: led live streaming and digital outreach operations.": "Coordinateur médias, First Baptist Church : diffusion en direct et opérations de communication digitale.",
      "Intern and Computer Apprentice, Zacest Computer Center: foundation in office tools, graphics, and animation.": "Stagiaire et apprenti informatique, Zacest Computer Center : bases en bureautique, graphisme et animation.",
      "Education": "Formation",
      "B.Tech, Industrial Mathematics (2018 - 2024)": "B.Tech, Mathématiques industrielles (2018 - 2024)",
      "Key Achievements": "Réalisations clés",
      "Delivered over 20 client projects with strong quality outcomes.": "Livraison de plus de 20 projets clients avec des résultats solides.",
      "Met 100% of project deadlines through effective planning and communication.": "Respect de 100 % des délais grâce à une planification et une communication efficaces.",
      "Improved engagement by optimizing website performance and UX structure.": "Amélioration de l’engagement grâce à l’optimisation des performances web et de l’UX.",
      "Leadership and Interests": "Leadership et centres d’intérêt",
      "Open-source contributor, tech mentor, and workshop facilitator.": "Contributeur open source, mentor tech et animateur d’ateliers.",
      "Languages: English (Fluent), Yoruba (Native), Pidgin (Conversational).": "Langues : anglais (courant), yoruba (natif), pidgin (conversationnel).",
      "Interests: AI applications, cloud technology, digital art, and web/mobile trend blogging.": "Intérêts : applications IA, cloud, art digital et veille web/mobile.",
      "Projects and Portfolio": "Projets et portfolio",
      "Production platforms across media, education, banking, and developer education.": "Plateformes en production pour les médias, l’éducation, la banque et la formation des développeurs.",
      "Media Website": "Site média",
      "School Website": "Site scolaire",
      "Bank Website": "Site bancaire",
      "Banking Platform": "Plateforme bancaire",
      "EdTech Platform": "Plateforme EdTech",
      "Blog and Portfolio": "Blog et portfolio",
      "Client Websites": "Sites clients",
      "Corporate and Portfolio Systems": "Systèmes corporate et portfolio",
      "Multiple client sectors": "Plusieurs secteurs clients",
      "Built, maintain, and update station website while integrating growth-focused digital operations.": "Création, maintenance et mise à jour du site de la station avec des opérations digitales orientées croissance.",
      "Developed website and management suite with records, result uploads, report cards, and dashboards.": "Développement du site et d’une suite de gestion avec dossiers, résultats, bulletins et tableaux de bord.",
      "Secure, responsive banking web experience focused on trust and discoverability.": "Expérience web bancaire sécurisée et responsive, centrée sur la confiance et la visibilité.",
      "Learning platform with videos, PDFs, audio lessons, career roadmaps, and certification flow.": "Plateforme d’apprentissage avec vidéos, PDF, leçons audio, parcours de carrière et certification.",
      "Personal blog and portfolio system with admin dashboard and SEO-focused content architecture.": "Système personnel de blog et portfolio avec tableau de bord admin et architecture SEO.",
      "SEO-optimized business and portfolio websites that improve online visibility and engagement.": "Sites business et portfolio optimisés SEO pour améliorer la visibilité et l’engagement.",
      "Visit Website": "Visiter le site",
      "What Clients Say": "Ce que disent les clients",
      "Trusted by schools, media brands, and businesses for reliable delivery and clear communication.": "Reconnu par des écoles, médias et entreprises pour une livraison fiable et une communication claire.",
      "All": "Tout",
      "Media": "Médias",
      "Education": "Éducation",
      "Finance": "Finance",
      "Corporate": "Entreprise",
      "Book a Call": "Réserver un appel",
      "Let's Discuss Your Project": "Discutons de votre projet",
      "Book a 20-minute discovery call to review your goals, timeline, and best technical approach for your website or platform.": "Réservez un appel découverte de 20 minutes pour revoir vos objectifs, votre calendrier et la meilleure approche technique pour votre site ou plateforme.",
      "Book a Call on Calendly": "Réserver sur Calendly",
      "Chat on WhatsApp": "Discuter sur WhatsApp",
      "Frequently Asked Questions": "Questions fréquentes",
      "Quick answers to common questions about process, delivery, and collaboration.": "Réponses rapides aux questions courantes sur le processus, la livraison et la collaboration.",
      "Process": "Processus",
      "Technical": "Technique",
      "Support": "Support",
      "Search question...": "Rechercher une question...",
      "No FAQ matched your search. Try another keyword.": "Aucune question ne correspond à votre recherche. Essayez un autre mot-clé.",
      "Get In Touch": "Prendre contact",
      "I am open to full-time roles, contract projects, and strategic collaborations in software engineering, digital product delivery, and EdTech platforms.": "Je suis ouvert aux postes à temps plein, missions contractuelles et collaborations stratégiques en ingénierie logicielle, livraison de produits numériques et plateformes EdTech.",
      "Social Media": "Réseaux sociaux",
      "Send a Message": "Envoyer un message",
      "Name": "Nom",
      "Subject": "Objet",
      "Message": "Message",
      "Send Message": "Envoyer le message",
      "New Portfolio Contact Message": "Nouveau message de contact du portfolio",
      "Copyright": "Droits d’auteur",
      "What kind of projects do you handle?": "Quels types de projets prenez-vous en charge ?",
      "I build and maintain websites, web applications, school systems, and digital platforms for media, education, banking, and business clients.": "Je crée et maintiens des sites web, applications web, systèmes scolaires et plateformes digitales pour les médias, l’éducation, la banque et les entreprises.",
      "How long does a typical project take?": "Combien de temps dure un projet typique ?",
      "Small websites usually take 1 to 3 weeks. Larger platforms can take 4 to 12 weeks depending on features, content readiness, and approvals.": "Les petits sites prennent généralement 1 à 3 semaines. Les plateformes plus grandes peuvent prendre 4 à 12 semaines selon les fonctionnalités, le contenu et les validations.",
      "Do you work on existing websites?": "Travaillez-vous sur des sites existants ?",
      "Yes. I redesign, optimize performance, fix bugs, add features, and improve SEO for existing websites and applications.": "Oui. Je refonds, optimise les performances, corrige les bugs, ajoute des fonctionnalités et améliore le SEO des sites et applications existants.",
      "What technologies do you use?": "Quelles technologies utilisez-vous ?",
      "My core stack includes Laravel, Vue.js, React, Tailwind CSS, Livewire, MySQL, and Alpine.js.": "Mon stack principal comprend Laravel, Vue.js, React, Tailwind CSS, Livewire, MySQL et Alpine.js.",
      "Do you provide maintenance after launch?": "Proposez-vous une maintenance après le lancement ?",
      "Yes. I provide post-launch support, updates, backups, and technical maintenance packages.": "Oui. Je propose du support après lancement, des mises à jour, des sauvegardes et des forfaits de maintenance technique.",
      "How do we start working together?": "Comment commençons-nous à travailler ensemble ?",
      "Book a discovery call on Calendly or send a message through the contact form. I will review your needs and share scope, timeline, and cost.": "Réservez un appel découverte sur Calendly ou envoyez un message via le formulaire. J’examinerai vos besoins et partagerai le périmètre, le calendrier et le coût.",
      "\"Adedayo rebuilt our station website and helped us run a stronger digital strategy. Our online engagement and brand visibility improved noticeably.\"": "\"Adedayo a reconstruit le site de notre station et nous a aidés à déployer une stratégie digitale plus forte. Notre engagement en ligne et notre visibilité ont nettement progressé.\"",
      "\"He delivered both our school website and management system with features that made administration easier for staff and parents.\"": "\"Il a livré notre site scolaire et notre système de gestion avec des fonctionnalités qui simplifient l’administration pour le personnel et les parents.\"",
      "\"From planning to deployment, the process was professional. The final website reflects our institution and works smoothly across devices.\"": "\"De la planification au déploiement, le processus a été professionnel. Le site final reflète notre institution et fonctionne très bien sur tous les appareils.\"",
      "\"Communication was clear, timelines were respected, and every revision was handled quickly.\"": "\"La communication était claire, les délais respectés et chaque révision traitée rapidement.\"",
      "\"Our new platform feels modern, fast, and easy to manage. We have seen better user response since launch.\"": "\"Notre nouvelle plateforme est moderne, rapide et facile à gérer. Nous avons observé une meilleure réaction des utilisateurs depuis le lancement.\"",
      "\"Adedayo combines technical depth with business understanding. He does not just build pages, he solves real workflow problems.\"": "\"Adedayo combine profondeur technique et compréhension business. Il ne crée pas seulement des pages, il résout de vrais problèmes de workflow.\"",
      "Management": "Direction",
      "Academic Office": "Bureau académique",
      "Admin Lead": "Responsable administratif",
      "Operations Unit": "Unité des opérations",
      "Operations Team": "Équipe opérations",
      "Client (NDA)": "Client (NDA)",
      "Founder": "Fondateur",
      "Product Lead": "Responsable produit",
      "Director": "Directeur",
      "SME Corporate Website": "Site corporate PME",
      "Business Platform Project": "Projet de plateforme business",
      "Enterprise Web Project": "Projet web entreprise",
      "Saved message draft restored on this device.": "Brouillon de message restauré sur cet appareil.",
      "Connection restored. Fresh content is available again.": "Connexion rétablie. Le contenu à jour est de nouveau disponible.",
      "You are offline. Cached pages and saved message drafts are still available.": "Vous êtes hors ligne. Les pages en cache et les brouillons restent disponibles.",
      "You are offline. Your draft is saved on this device and can be sent when you reconnect.": "Vous êtes hors ligne. Votre brouillon est enregistré sur cet appareil et pourra être envoyé à la reconnexion.",
      "Thanks. Your message was submitted successfully.": "Merci. Votre message a bien été envoyé."
    },
    ar: {
      "Menu": "القائمة",
      "Toggle menu": "تبديل القائمة",
      "Home": "الرئيسية",
      "About": "نبذة",
      "Skills": "المهارات",
      "Experience": "الخبرة",
      "Projects": "المشاريع",
      "Contact": "تواصل",
      "Language": "اللغة",
      "Full-Stack Web Developer | EdTech and Digital Growth": "مطور ويب Full-Stack | تقنيات التعليم والنمو الرقمي",
      "Full-Stack Web Developer": "مطور ويب Full-Stack",
      "I build and maintain scalable, user-centric applications for schools, media, and corporate teams. My stack includes Laravel, Vue.js, React, and Tailwind CSS, backed by practical product delivery and digital growth strategy.": "أبني وأدير تطبيقات قابلة للتوسع ومتمحورة حول المستخدم للمدارس ووسائل الإعلام وفرق الشركات. تشمل أدواتي Laravel وVue.js وReact وTailwind CSS، مدعومة بخبرة عملية في تسليم المنتجات واستراتيجية النمو الرقمي.",
      "Hire Me": "وظفني",
      "View Projects": "عرض المشاريع",
      "20+ Projects": "أكثر من 20 مشروعاً",
      "Enterprise and client delivery": "تسليم للمؤسسات والعملاء",
      "30% Faster": "أسرع بنسبة 30%",
      "Reduced project timelines": "تقليل مدة المشاريع",
      "100% Deadlines": "الالتزام بكل المواعيد",
      "Consistent client delivery": "تسليم ثابت للعملاء",
      "2026-Present": "2026 - حتى الآن",
      "Digital and Web Specialist, Glow FM": "أخصائي رقمي وويب، Glow FM",
      "Available for collaboration": "متاح للتعاون",
      "Portrait of Adedayo Ebenezer Oyetoke": "صورة أديدايو إبنيزر أويتوك",
      "Full-Stack Developer and Tech Educator": "مطور Full-Stack ومعلّم تقني",
      "Web": "ويب",
      "Growth": "نمو",
      "Location": "الموقع",
      "Current Role": "الدور الحالي",
      "Founder, Wireless": "مؤسس Wireless",
      "Professional Summary": "ملخص مهني",
      "Full-Stack Web Developer and Digital and EdTech Specialist with hands-on expertise in Laravel, Vue.js, React, and Tailwind CSS. I build and maintain websites, manage digital growth, and deliver scalable applications for schools, media, and business clients.": "مطور ويب Full-Stack ومتخصص رقمي وEdTech بخبرة عملية في Laravel وVue.js وReact وTailwind CSS. أبني وأدير المواقع، وأقود النمو الرقمي، وأسلم تطبيقات قابلة للتوسع للمدارس والإعلام والعملاء التجاريين.",
      "I am also the founder of BootKode, a tech-education platform focused on project-based learning for aspiring developers. I am passionate about AI, cloud technologies, mentorship, and measurable product outcomes.": "أنا أيضاً مؤسس BootKode، وهي منصة تعليم تقني تركز على التعلم بالمشاريع للمطورين الطموحين. أهتم بالذكاء الاصطناعي وتقنيات السحابة والإرشاد ونتائج المنتجات القابلة للقياس.",
      "Contact Snapshot": "ملخص التواصل",
      "Address": "العنوان",
      "Address:": "العنوان:",
      "Email": "البريد الإلكتروني",
      "Email:": "البريد الإلكتروني:",
      "Phone": "الهاتف",
      "Phone:": "الهاتف:",
      "Website": "الموقع",
      "Website:": "الموقع:",
      "Core Technical Skills": "المهارات التقنية الأساسية",
      "Practical stack for full lifecycle product delivery across web and EdTech systems.": "مجموعة أدوات عملية لتسليم المنتجات عبر دورة الحياة الكاملة في أنظمة الويب وEdTech.",
      "Frontend": "الواجهة الأمامية",
      "Backend": "الخلفية",
      "Mobile and Data": "الموبايل والبيانات",
      "Tools and Design": "الأدوات والتصميم",
      "Frontend Delivery": "تسليم الواجهة",
      "Backend Delivery": "تسليم الخلفية",
      "Digital Growth Strategy": "استراتيجية النمو الرقمي",
      "Problem Solving": "حل المشكلات",
      "Professional Experience": "الخبرة المهنية",
      "Full SDLC delivery across web engineering, education technology, and digital media operations.": "تسليم كامل لدورة تطوير البرمجيات في هندسة الويب وتقنيات التعليم وعمليات الإعلام الرقمي.",
      "2022 - Present": "2022 - حتى الآن",
      "Founder and Lead Developer, Wireless Computer Services": "المؤسس والمطور الرئيسي، Wireless Computer Services",
      "Designed and deployed 20+ enterprise-grade applications for school, banking, corporate, and government clients.": "صممت ونشرت أكثر من 20 تطبيقاً بمستوى مؤسسي لعملاء في التعليم والبنوك والشركات والحكومة.",
      "Reduced project timelines by 30% through Laravel backend and Vue plus Tailwind integration.": "قللت مدة المشاريع بنسبة 30% عبر خلفية Laravel وتكامل Vue مع Tailwind.",
      "Led end-to-end SDLC: requirements, architecture, implementation, deployment, and maintenance.": "قدت دورة التطوير من البداية للنهاية: المتطلبات، المعمارية، التنفيذ، النشر، والصيانة.",
      "January 2026 - Present": "يناير 2026 - حتى الآن",
      "Digital and Web Specialist, Glow 99.1 FM (Akure)": "أخصائي رقمي وويب، Glow 99.1 FM (Akure)",
      "Built and maintain the station website: www.glowfmradio.com.": "بنيت وأدير موقع المحطة: www.glowfmradio.com.",
      "Manage social media growth, audience engagement, and monetization campaigns.": "أدير نمو الشبكات الاجتماعية وتفاعل الجمهور وحملات تحقيق الدخل.",
      "Execute digital strategy and analytics optimization aligned with station objectives.": "أنفذ الاستراتيجية الرقمية وتحسين التحليلات بما يتماشى مع أهداف المحطة.",
      "2025 | Anambra State": "2025 | ولاية أنامبرا",
      "NYSC Teacher and Developer, Elites International College": "مدرس ومطور NYSC، Elites International College",
      "Taught Senior Secondary Mathematics and Physics using structured, problem-solving methods.": "درست الرياضيات والفيزياء للمرحلة الثانوية العليا بأساليب منظمة لحل المشكلات.",
      "Built school website and full management system from scratch with multi-role dashboards.": "بنيت موقع المدرسة ونظام إدارة كامل من الصفر مع لوحات تحكم متعددة الأدوار.",
      "Implemented records, result processing, payments, CBT, e-learning, and announcement modules.": "نفذت وحدات السجلات ومعالجة النتائج والمدفوعات والاختبارات الإلكترونية والتعلم الإلكتروني والإعلانات.",
      "Freelance and Earlier Roles": "أعمال حرة وأدوار سابقة",
      "Freelance Web Developer and Consultant: built school, portfolio, e-commerce, and business sites.": "مطور ويب ومستشار مستقل: بنيت مواقع مدرسية وشخصية وتجارية ومواقع أعمال.",
      "Media Coordinator, First Baptist Church: led live streaming and digital outreach operations.": "منسق إعلامي، First Baptist Church: قدت البث المباشر وعمليات التواصل الرقمي.",
      "Intern and Computer Apprentice, Zacest Computer Center: foundation in office tools, graphics, and animation.": "متدرب في Zacest Computer Center: أساس في أدوات المكتب والتصميم والرسوم المتحركة.",
      "Education": "التعليم",
      "B.Tech, Industrial Mathematics (2018 - 2024)": "بكالوريوس تقنية، الرياضيات الصناعية (2018 - 2024)",
      "Key Achievements": "إنجازات رئيسية",
      "Delivered over 20 client projects with strong quality outcomes.": "سلمت أكثر من 20 مشروعاً للعملاء بنتائج جودة قوية.",
      "Met 100% of project deadlines through effective planning and communication.": "حققت 100% من مواعيد التسليم عبر التخطيط والتواصل الفعال.",
      "Improved engagement by optimizing website performance and UX structure.": "حسنت التفاعل عبر تحسين أداء المواقع وبنية تجربة المستخدم.",
      "Leadership and Interests": "القيادة والاهتمامات",
      "Open-source contributor, tech mentor, and workshop facilitator.": "مساهم في المصادر المفتوحة، ومرشد تقني، ومنظم ورش عمل.",
      "Languages: English (Fluent), Yoruba (Native), Pidgin (Conversational).": "اللغات: الإنجليزية (بطلاقة)، اليوروبا (لغة أم)، البيدجن (محادثة).",
      "Interests: AI applications, cloud technology, digital art, and web/mobile trend blogging.": "الاهتمامات: تطبيقات الذكاء الاصطناعي، تقنيات السحابة، الفن الرقمي، وكتابة اتجاهات الويب والموبايل.",
      "Projects and Portfolio": "المشاريع والأعمال",
      "Production platforms across media, education, banking, and developer education.": "منصات إنتاجية في الإعلام والتعليم والبنوك وتعليم المطورين.",
      "Media Website": "موقع إعلامي",
      "School Website": "موقع مدرسة",
      "Bank Website": "موقع بنك",
      "Banking Platform": "منصة مصرفية",
      "EdTech Platform": "منصة EdTech",
      "Blog and Portfolio": "مدونة وأعمال",
      "Client Websites": "مواقع العملاء",
      "Corporate and Portfolio Systems": "أنظمة الشركات والأعمال",
      "Multiple client sectors": "قطاعات عملاء متعددة",
      "Built, maintain, and update station website while integrating growth-focused digital operations.": "بناء وصيانة وتحديث موقع المحطة مع دمج عمليات رقمية تركز على النمو.",
      "Developed website and management suite with records, result uploads, report cards, and dashboards.": "طورت موقعاً وحزمة إدارة تشمل السجلات ورفع النتائج وبطاقات التقرير ولوحات التحكم.",
      "Secure, responsive banking web experience focused on trust and discoverability.": "تجربة ويب مصرفية آمنة ومتجاوبة تركز على الثقة وسهولة الاكتشاف.",
      "Learning platform with videos, PDFs, audio lessons, career roadmaps, and certification flow.": "منصة تعلم تحتوي على فيديوهات وملفات PDF ودروس صوتية وخرائط مهنية ومسار شهادات.",
      "Personal blog and portfolio system with admin dashboard and SEO-focused content architecture.": "نظام مدونة وأعمال شخصي مع لوحة إدارة وبنية محتوى تركز على SEO.",
      "SEO-optimized business and portfolio websites that improve online visibility and engagement.": "مواقع أعمال ومحافظ محسنة لمحركات البحث تزيد الظهور والتفاعل.",
      "Visit Website": "زيارة الموقع",
      "What Clients Say": "ماذا يقول العملاء",
      "Trusted by schools, media brands, and businesses for reliable delivery and clear communication.": "موثوق من المدارس والعلامات الإعلامية والشركات بسبب التسليم الموثوق والتواصل الواضح.",
      "All": "الكل",
      "Media": "إعلام",
      "Education": "تعليم",
      "Finance": "مالية",
      "Corporate": "شركات",
      "Book a Call": "احجز مكالمة",
      "Let's Discuss Your Project": "لنتحدث عن مشروعك",
      "Book a 20-minute discovery call to review your goals, timeline, and best technical approach for your website or platform.": "احجز مكالمة تعريفية لمدة 20 دقيقة لمراجعة أهدافك والجدول الزمني وأفضل نهج تقني لموقعك أو منصتك.",
      "Book a Call on Calendly": "احجز عبر Calendly",
      "Chat on WhatsApp": "تحدث عبر واتساب",
      "Frequently Asked Questions": "الأسئلة الشائعة",
      "Quick answers to common questions about process, delivery, and collaboration.": "إجابات سريعة عن الأسئلة الشائعة حول العملية والتسليم والتعاون.",
      "Process": "العملية",
      "Technical": "تقني",
      "Support": "الدعم",
      "Search question...": "ابحث عن سؤال...",
      "No FAQ matched your search. Try another keyword.": "لا توجد أسئلة مطابقة. جرب كلمة أخرى.",
      "Get In Touch": "تواصل معي",
      "I am open to full-time roles, contract projects, and strategic collaborations in software engineering, digital product delivery, and EdTech platforms.": "أنا متاح لوظائف بدوام كامل ومشاريع تعاقدية وتعاونات استراتيجية في هندسة البرمجيات وتسليم المنتجات الرقمية ومنصات EdTech.",
      "Social Media": "وسائل التواصل",
      "Send a Message": "إرسال رسالة",
      "Name": "الاسم",
      "Subject": "الموضوع",
      "Message": "الرسالة",
      "Send Message": "إرسال الرسالة",
      "New Portfolio Contact Message": "رسالة تواصل جديدة من الملف الشخصي",
      "Copyright": "حقوق النشر",
      "What kind of projects do you handle?": "ما نوع المشاريع التي تنفذها؟",
      "I build and maintain websites, web applications, school systems, and digital platforms for media, education, banking, and business clients.": "أبني وأدير مواقع وتطبيقات ويب وأنظمة مدرسية ومنصات رقمية للإعلام والتعليم والبنوك والعملاء التجاريين.",
      "How long does a typical project take?": "كم يستغرق المشروع عادة؟",
      "Small websites usually take 1 to 3 weeks. Larger platforms can take 4 to 12 weeks depending on features, content readiness, and approvals.": "المواقع الصغيرة تستغرق عادة من أسبوع إلى 3 أسابيع. المنصات الأكبر قد تستغرق من 4 إلى 12 أسبوعاً حسب الميزات وجاهزية المحتوى والموافقات.",
      "Do you work on existing websites?": "هل تعمل على مواقع موجودة؟",
      "Yes. I redesign, optimize performance, fix bugs, add features, and improve SEO for existing websites and applications.": "نعم. أعيد التصميم، وأحسن الأداء، وأصلح الأخطاء، وأضيف الميزات، وأحسن SEO للمواقع والتطبيقات الحالية.",
      "What technologies do you use?": "ما التقنيات التي تستخدمها؟",
      "My core stack includes Laravel, Vue.js, React, Tailwind CSS, Livewire, MySQL, and Alpine.js.": "تشمل أدواتي الأساسية Laravel وVue.js وReact وTailwind CSS وLivewire وMySQL وAlpine.js.",
      "Do you provide maintenance after launch?": "هل تقدم صيانة بعد الإطلاق؟",
      "Yes. I provide post-launch support, updates, backups, and technical maintenance packages.": "نعم. أقدم دعماً بعد الإطلاق وتحديثات ونسخاً احتياطية وباقات صيانة تقنية.",
      "How do we start working together?": "كيف نبدأ العمل معاً؟",
      "Book a discovery call on Calendly or send a message through the contact form. I will review your needs and share scope, timeline, and cost.": "احجز مكالمة تعريفية على Calendly أو أرسل رسالة عبر نموذج التواصل. سأراجع احتياجاتك وأشارك النطاق والمدة والتكلفة.",
      "Saved message draft restored on this device.": "تمت استعادة مسودة الرسالة على هذا الجهاز.",
      "Connection restored. Fresh content is available again.": "تمت استعادة الاتصال. المحتوى الجديد متاح مرة أخرى.",
      "You are offline. Cached pages and saved message drafts are still available.": "أنت غير متصل. الصفحات المخزنة والمسودات المحفوظة لا تزال متاحة.",
      "You are offline. Your draft is saved on this device and can be sent when you reconnect.": "أنت غير متصل. تم حفظ مسودتك على هذا الجهاز ويمكن إرسالها عند عودة الاتصال.",
      "Thanks. Your message was submitted successfully.": "شكراً. تم إرسال رسالتك بنجاح."
    },
    sw: {
      "Menu": "Menyu",
      "Toggle menu": "Fungua au funga menyu",
      "Home": "Nyumbani",
      "About": "Kuhusu",
      "Skills": "Ujuzi",
      "Experience": "Uzoefu",
      "Projects": "Miradi",
      "Contact": "Mawasiliano",
      "Language": "Lugha",
      "Full-Stack Web Developer | EdTech and Digital Growth": "Msanidi wa Wavuti Full-Stack | EdTech na Ukuaji wa Kidijitali",
      "Full-Stack Web Developer": "Msanidi wa Wavuti Full-Stack",
      "I build and maintain scalable, user-centric applications for schools, media, and corporate teams. My stack includes Laravel, Vue.js, React, and Tailwind CSS, backed by practical product delivery and digital growth strategy.": "Ninajenga na kudumisha programu zinazokua na zinazomlenga mtumiaji kwa shule, vyombo vya habari na timu za kampuni. Natumia Laravel, Vue.js, React na Tailwind CSS, pamoja na uzoefu wa kutoa bidhaa na mkakati wa ukuaji wa kidijitali.",
      "Hire Me": "Niajiri",
      "View Projects": "Tazama miradi",
      "20+ Projects": "Miradi 20+",
      "Enterprise and client delivery": "Uwasilishaji kwa taasisi na wateja",
      "30% Faster": "Haraka zaidi kwa 30%",
      "Reduced project timelines": "Muda wa miradi umepunguzwa",
      "100% Deadlines": "Makataa 100%",
      "Consistent client delivery": "Uwasilishaji thabiti kwa wateja",
      "2026-Present": "2026 - Sasa",
      "Digital and Web Specialist, Glow FM": "Mtaalamu wa Dijitali na Wavuti, Glow FM",
      "Available for collaboration": "Niko tayari kwa ushirikiano",
      "Full-Stack Developer and Tech Educator": "Msanidi Full-Stack na Mwalimu wa Teknolojia",
      "Growth": "Ukuaji",
      "Location": "Eneo",
      "Current Role": "Nafasi ya sasa",
      "Founder, Wireless": "Mwanzilishi, Wireless",
      "Professional Summary": "Muhtasari wa kitaaluma",
      "Full-Stack Web Developer and Digital and EdTech Specialist with hands-on expertise in Laravel, Vue.js, React, and Tailwind CSS. I build and maintain websites, manage digital growth, and deliver scalable applications for schools, media, and business clients.": "Msanidi wa wavuti full-stack na mtaalamu wa dijitali na EdTech mwenye uzoefu wa moja kwa moja katika Laravel, Vue.js, React na Tailwind CSS. Ninajenga na kudumisha tovuti, kusimamia ukuaji wa kidijitali na kutoa programu zinazokua kwa shule, vyombo vya habari na wateja wa biashara.",
      "I am also the founder of BootKode, a tech-education platform focused on project-based learning for aspiring developers. I am passionate about AI, cloud technologies, mentorship, and measurable product outcomes.": "Pia mimi ni mwanzilishi wa BootKode, jukwaa la elimu ya teknolojia linalolenga kujifunza kupitia miradi kwa wasanidi wanaochipukia. Napenda AI, teknolojia za wingu, ushauri na matokeo ya bidhaa yanayopimika.",
      "Contact Snapshot": "Muhtasari wa mawasiliano",
      "Address": "Anwani",
      "Address:": "Anwani:",
      "Email": "Barua pepe",
      "Email:": "Barua pepe:",
      "Phone": "Simu",
      "Phone:": "Simu:",
      "Website": "Tovuti",
      "Website:": "Tovuti:",
      "Core Technical Skills": "Ujuzi muhimu wa kiufundi",
      "Practical stack for full lifecycle product delivery across web and EdTech systems.": "Zana za vitendo kwa mzunguko mzima wa utoaji wa bidhaa katika mifumo ya wavuti na EdTech.",
      "Mobile and Data": "Simu na data",
      "Tools and Design": "Zana na ubunifu",
      "Frontend Delivery": "Uwasilishaji wa frontend",
      "Backend Delivery": "Uwasilishaji wa backend",
      "Digital Growth Strategy": "Mkakati wa ukuaji wa kidijitali",
      "Problem Solving": "Utatuzi wa matatizo",
      "Professional Experience": "Uzoefu wa kitaaluma",
      "Full SDLC delivery across web engineering, education technology, and digital media operations.": "Uwasilishaji kamili wa SDLC katika uhandisi wa wavuti, teknolojia ya elimu na shughuli za vyombo vya habari vya kidijitali.",
      "2022 - Present": "2022 - Sasa",
      "Founder and Lead Developer, Wireless Computer Services": "Mwanzilishi na Msanidi Mkuu, Wireless Computer Services",
      "Designed and deployed 20+ enterprise-grade applications for school, banking, corporate, and government clients.": "Nilibuni na kusambaza programu 20+ za kiwango cha taasisi kwa wateja wa shule, benki, kampuni na serikali.",
      "Reduced project timelines by 30% through Laravel backend and Vue plus Tailwind integration.": "Nilipunguza muda wa miradi kwa 30% kupitia backend ya Laravel na ujumuishaji wa Vue na Tailwind.",
      "Led end-to-end SDLC: requirements, architecture, implementation, deployment, and maintenance.": "Niliongoza SDLC kutoka mwanzo hadi mwisho: mahitaji, usanifu, utekelezaji, usambazaji na matengenezo.",
      "January 2026 - Present": "Januari 2026 - Sasa",
      "Digital and Web Specialist, Glow 99.1 FM (Akure)": "Mtaalamu wa Dijitali na Wavuti, Glow 99.1 FM (Akure)",
      "Built and maintain the station website: www.glowfmradio.com.": "Nilijenga na kudumisha tovuti ya kituo: www.glowfmradio.com.",
      "Manage social media growth, audience engagement, and monetization campaigns.": "Nasimamia ukuaji wa mitandao ya kijamii, ushiriki wa hadhira na kampeni za mapato.",
      "Execute digital strategy and analytics optimization aligned with station objectives.": "Ninatekeleza mkakati wa kidijitali na kuboresha takwimu kulingana na malengo ya kituo.",
      "Education": "Elimu",
      "Key Achievements": "Mafanikio muhimu",
      "Delivered over 20 client projects with strong quality outcomes.": "Nimewasilisha miradi zaidi ya 20 ya wateja yenye matokeo bora.",
      "Met 100% of project deadlines through effective planning and communication.": "Nilitimiza makataa yote kupitia mipango na mawasiliano bora.",
      "Leadership and Interests": "Uongozi na mambo ninayopenda",
      "Projects and Portfolio": "Miradi na portifolio",
      "Production platforms across media, education, banking, and developer education.": "Majukwaa ya uzalishaji katika vyombo vya habari, elimu, benki na elimu ya wasanidi.",
      "Media Website": "Tovuti ya media",
      "School Website": "Tovuti ya shule",
      "Bank Website": "Tovuti ya benki",
      "Banking Platform": "Jukwaa la benki",
      "EdTech Platform": "Jukwaa la EdTech",
      "Blog and Portfolio": "Blogu na portifolio",
      "Client Websites": "Tovuti za wateja",
      "Visit Website": "Tembelea tovuti",
      "What Clients Say": "Wateja wanasema nini",
      "Trusted by schools, media brands, and businesses for reliable delivery and clear communication.": "Ninaaminiwa na shule, chapa za media na biashara kwa uwasilishaji wa kuaminika na mawasiliano wazi.",
      "All": "Zote",
      "Media": "Media",
      "Finance": "Fedha",
      "Corporate": "Kampuni",
      "Book a Call": "Weka miadi ya simu",
      "Let's Discuss Your Project": "Tujadili mradi wako",
      "Book a 20-minute discovery call to review your goals, timeline, and best technical approach for your website or platform.": "Weka miadi ya dakika 20 ili kupitia malengo yako, muda na njia bora ya kiufundi kwa tovuti au jukwaa lako.",
      "Book a Call on Calendly": "Weka miadi kwenye Calendly",
      "Chat on WhatsApp": "Ongea WhatsApp",
      "Frequently Asked Questions": "Maswali yanayoulizwa mara kwa mara",
      "Quick answers to common questions about process, delivery, and collaboration.": "Majibu mafupi kuhusu mchakato, uwasilishaji na ushirikiano.",
      "Process": "Mchakato",
      "Technical": "Kiufundi",
      "Support": "Msaada",
      "Search question...": "Tafuta swali...",
      "Get In Touch": "Wasiliana nami",
      "Social Media": "Mitandao ya kijamii",
      "Send a Message": "Tuma ujumbe",
      "Name": "Jina",
      "Subject": "Mada",
      "Message": "Ujumbe",
      "Send Message": "Tuma ujumbe",
      "What kind of projects do you handle?": "Unashughulikia miradi ya aina gani?",
      "How long does a typical project take?": "Mradi wa kawaida huchukua muda gani?",
      "Do you work on existing websites?": "Je, unafanya kazi kwenye tovuti zilizopo?",
      "What technologies do you use?": "Unatumia teknolojia gani?",
      "Do you provide maintenance after launch?": "Je, unatoa matengenezo baada ya kuzindua?",
      "How do we start working together?": "Tunaanzaje kufanya kazi pamoja?",
      "Thanks. Your message was submitted successfully.": "Asante. Ujumbe wako umetumwa kikamilifu."
    },
    hi: {
      "Menu": "मेनू",
      "Toggle menu": "मेनू खोलें या बंद करें",
      "Home": "होम",
      "About": "परिचय",
      "Skills": "कौशल",
      "Experience": "अनुभव",
      "Projects": "प्रोजेक्ट्स",
      "Contact": "संपर्क",
      "Language": "भाषा",
      "Full-Stack Web Developer | EdTech and Digital Growth": "फुल-स्टैक वेब डेवलपर | EdTech और डिजिटल ग्रोथ",
      "Full-Stack Web Developer": "फुल-स्टैक वेब डेवलपर",
      "I build and maintain scalable, user-centric applications for schools, media, and corporate teams. My stack includes Laravel, Vue.js, React, and Tailwind CSS, backed by practical product delivery and digital growth strategy.": "मैं स्कूलों, मीडिया और कॉर्पोरेट टीमों के लिए स्केलेबल और यूज़र-केंद्रित एप्लिकेशन बनाता और बनाए रखता हूँ। मेरा स्टैक Laravel, Vue.js, React और Tailwind CSS है, जिसमें प्रोडक्ट डिलीवरी और डिजिटल ग्रोथ रणनीति का व्यावहारिक अनुभव शामिल है।",
      "Hire Me": "मुझे हायर करें",
      "View Projects": "प्रोजेक्ट देखें",
      "20+ Projects": "20+ प्रोजेक्ट",
      "Enterprise and client delivery": "एंटरप्राइज और क्लाइंट डिलीवरी",
      "30% Faster": "30% तेज",
      "Reduced project timelines": "प्रोजेक्ट समयसीमा कम की",
      "100% Deadlines": "100% समयसीमा",
      "Consistent client delivery": "लगातार क्लाइंट डिलीवरी",
      "2026-Present": "2026 - वर्तमान",
      "Digital and Web Specialist, Glow FM": "डिजिटल और वेब विशेषज्ञ, Glow FM",
      "Available for collaboration": "सहयोग के लिए उपलब्ध",
      "Full-Stack Developer and Tech Educator": "फुल-स्टैक डेवलपर और टेक शिक्षक",
      "Growth": "ग्रोथ",
      "Location": "स्थान",
      "Current Role": "वर्तमान भूमिका",
      "Founder, Wireless": "संस्थापक, Wireless",
      "Professional Summary": "पेशेवर सारांश",
      "Full-Stack Web Developer and Digital and EdTech Specialist with hands-on expertise in Laravel, Vue.js, React, and Tailwind CSS. I build and maintain websites, manage digital growth, and deliver scalable applications for schools, media, and business clients.": "Laravel, Vue.js, React और Tailwind CSS में व्यावहारिक अनुभव वाला फुल-स्टैक वेब डेवलपर और डिजिटल व EdTech विशेषज्ञ। मैं स्कूलों, मीडिया और बिज़नेस क्लाइंट्स के लिए वेबसाइट बनाता और बनाए रखता हूँ, डिजिटल ग्रोथ संभालता हूँ और स्केलेबल एप्लिकेशन डिलीवर करता हूँ।",
      "I am also the founder of BootKode, a tech-education platform focused on project-based learning for aspiring developers. I am passionate about AI, cloud technologies, mentorship, and measurable product outcomes.": "मैं BootKode का संस्थापक भी हूँ, जो उभरते डेवलपर्स के लिए प्रोजेक्ट-आधारित सीखने पर केंद्रित टेक-एजुकेशन प्लेटफॉर्म है। मुझे AI, क्लाउड तकनीक, मेंटरशिप और मापने योग्य प्रोडक्ट परिणामों में रुचि है।",
      "Contact Snapshot": "संपर्क सारांश",
      "Address": "पता",
      "Address:": "पता:",
      "Email": "ईमेल",
      "Email:": "ईमेल:",
      "Phone": "फोन",
      "Phone:": "फोन:",
      "Website": "वेबसाइट",
      "Website:": "वेबसाइट:",
      "Core Technical Skills": "मुख्य तकनीकी कौशल",
      "Practical stack for full lifecycle product delivery across web and EdTech systems.": "वेब और EdTech सिस्टम में पूरे प्रोडक्ट लाइफसाइकिल के लिए व्यावहारिक स्टैक।",
      "Mobile and Data": "मोबाइल और डेटा",
      "Tools and Design": "टूल्स और डिज़ाइन",
      "Frontend Delivery": "Frontend डिलीवरी",
      "Backend Delivery": "Backend डिलीवरी",
      "Digital Growth Strategy": "डिजिटल ग्रोथ रणनीति",
      "Problem Solving": "समस्या समाधान",
      "Professional Experience": "पेशेवर अनुभव",
      "Full SDLC delivery across web engineering, education technology, and digital media operations.": "वेब इंजीनियरिंग, शिक्षा तकनीक और डिजिटल मीडिया संचालन में पूर्ण SDLC डिलीवरी।",
      "2022 - Present": "2022 - वर्तमान",
      "Founder and Lead Developer, Wireless Computer Services": "संस्थापक और लीड डेवलपर, Wireless Computer Services",
      "Designed and deployed 20+ enterprise-grade applications for school, banking, corporate, and government clients.": "स्कूल, बैंकिंग, कॉर्पोरेट और सरकारी क्लाइंट्स के लिए 20+ एंटरप्राइज-ग्रेड एप्लिकेशन डिज़ाइन और डिप्लॉय किए।",
      "Reduced project timelines by 30% through Laravel backend and Vue plus Tailwind integration.": "Laravel backend और Vue + Tailwind इंटीग्रेशन से प्रोजेक्ट समयसीमा 30% कम की।",
      "Led end-to-end SDLC: requirements, architecture, implementation, deployment, and maintenance.": "पूरे SDLC का नेतृत्व किया: आवश्यकताएँ, आर्किटेक्चर, इम्प्लीमेंटेशन, डिप्लॉयमेंट और मेंटेनेंस।",
      "January 2026 - Present": "जनवरी 2026 - वर्तमान",
      "Digital and Web Specialist, Glow 99.1 FM (Akure)": "डिजिटल और वेब विशेषज्ञ, Glow 99.1 FM (Akure)",
      "Education": "शिक्षा",
      "Key Achievements": "मुख्य उपलब्धियाँ",
      "Leadership and Interests": "नेतृत्व और रुचियाँ",
      "Projects and Portfolio": "प्रोजेक्ट्स और पोर्टफोलियो",
      "Visit Website": "वेबसाइट देखें",
      "What Clients Say": "क्लाइंट क्या कहते हैं",
      "All": "सभी",
      "Media": "मीडिया",
      "Education": "शिक्षा",
      "Finance": "वित्त",
      "Corporate": "कॉर्पोरेट",
      "Book a Call": "कॉल बुक करें",
      "Let's Discuss Your Project": "अपने प्रोजेक्ट पर बात करें",
      "Book a 20-minute discovery call to review your goals, timeline, and best technical approach for your website or platform.": "अपनी वेबसाइट या प्लेटफॉर्म के लिए लक्ष्य, समयसीमा और सही तकनीकी तरीका समझने के लिए 20 मिनट की डिस्कवरी कॉल बुक करें।",
      "Book a Call on Calendly": "Calendly पर कॉल बुक करें",
      "Chat on WhatsApp": "WhatsApp पर बात करें",
      "Frequently Asked Questions": "अक्सर पूछे जाने वाले प्रश्न",
      "Quick answers to common questions about process, delivery, and collaboration.": "प्रक्रिया, डिलीवरी और सहयोग से जुड़े सामान्य प्रश्नों के त्वरित उत्तर।",
      "Process": "प्रक्रिया",
      "Technical": "तकनीकी",
      "Support": "सपोर्ट",
      "Search question...": "प्रश्न खोजें...",
      "Get In Touch": "संपर्क करें",
      "Social Media": "सोशल मीडिया",
      "Send a Message": "संदेश भेजें",
      "Name": "नाम",
      "Subject": "विषय",
      "Message": "संदेश",
      "Send Message": "संदेश भेजें",
      "What kind of projects do you handle?": "आप किस तरह के प्रोजेक्ट करते हैं?",
      "How long does a typical project take?": "सामान्य प्रोजेक्ट में कितना समय लगता है?",
      "Do you work on existing websites?": "क्या आप मौजूदा वेबसाइटों पर काम करते हैं?",
      "What technologies do you use?": "आप कौन सी तकनीकें इस्तेमाल करते हैं?",
      "Do you provide maintenance after launch?": "लॉन्च के बाद मेंटेनेंस देते हैं?",
      "How do we start working together?": "हम साथ काम कैसे शुरू करें?",
      "Thanks. Your message was submitted successfully.": "धन्यवाद। आपका संदेश सफलतापूर्वक भेज दिया गया है।"
    },
    pt: {
      "Menu": "Menu",
      "Toggle menu": "Alternar menu",
      "Home": "Início",
      "About": "Sobre",
      "Skills": "Competências",
      "Experience": "Experiência",
      "Projects": "Projetos",
      "Contact": "Contato",
      "Language": "Idioma",
      "Full-Stack Web Developer | EdTech and Digital Growth": "Desenvolvedor Web Full-Stack | EdTech e Crescimento Digital",
      "Full-Stack Web Developer": "Desenvolvedor Web Full-Stack",
      "I build and maintain scalable, user-centric applications for schools, media, and corporate teams. My stack includes Laravel, Vue.js, React, and Tailwind CSS, backed by practical product delivery and digital growth strategy.": "Crio e mantenho aplicações escaláveis centradas no usuário para escolas, mídia e equipes corporativas. Meu stack inclui Laravel, Vue.js, React e Tailwind CSS, com experiência prática em entrega de produtos e estratégia de crescimento digital.",
      "Hire Me": "Contrate-me",
      "View Projects": "Ver projetos",
      "20+ Projects": "Mais de 20 projetos",
      "Enterprise and client delivery": "Entrega empresarial e para clientes",
      "30% Faster": "30% mais rápido",
      "Reduced project timelines": "Prazos de projeto reduzidos",
      "100% Deadlines": "100% dos prazos",
      "Consistent client delivery": "Entrega consistente para clientes",
      "2026-Present": "2026 - Presente",
      "Digital and Web Specialist, Glow FM": "Especialista Digital e Web, Glow FM",
      "Available for collaboration": "Disponível para colaboração",
      "Full-Stack Developer and Tech Educator": "Desenvolvedor Full-Stack e educador tech",
      "Growth": "Crescimento",
      "Location": "Localização",
      "Current Role": "Função atual",
      "Founder, Wireless": "Fundador, Wireless",
      "Professional Summary": "Resumo profissional",
      "Full-Stack Web Developer and Digital and EdTech Specialist with hands-on expertise in Laravel, Vue.js, React, and Tailwind CSS. I build and maintain websites, manage digital growth, and deliver scalable applications for schools, media, and business clients.": "Desenvolvedor web full-stack e especialista digital e EdTech com experiência prática em Laravel, Vue.js, React e Tailwind CSS. Crio e mantenho sites, gerencio crescimento digital e entrego aplicações escaláveis para escolas, mídia e clientes empresariais.",
      "I am also the founder of BootKode, a tech-education platform focused on project-based learning for aspiring developers. I am passionate about AI, cloud technologies, mentorship, and measurable product outcomes.": "Também sou fundador da BootKode, uma plataforma de educação tecnológica focada em aprendizagem baseada em projetos para futuros desenvolvedores. Tenho interesse por IA, cloud, mentoria e resultados de produto mensuráveis.",
      "Contact Snapshot": "Resumo de contato",
      "Address": "Endereço",
      "Address:": "Endereço:",
      "Email": "E-mail",
      "Email:": "E-mail:",
      "Phone": "Telefone",
      "Phone:": "Telefone:",
      "Website": "Site",
      "Website:": "Site:",
      "Core Technical Skills": "Principais competências técnicas",
      "Practical stack for full lifecycle product delivery across web and EdTech systems.": "Stack prático para entregar produtos em todo o ciclo de vida em sistemas web e EdTech.",
      "Mobile and Data": "Mobile e dados",
      "Tools and Design": "Ferramentas e design",
      "Frontend Delivery": "Entrega frontend",
      "Backend Delivery": "Entrega backend",
      "Digital Growth Strategy": "Estratégia de crescimento digital",
      "Problem Solving": "Resolução de problemas",
      "Professional Experience": "Experiência profissional",
      "Full SDLC delivery across web engineering, education technology, and digital media operations.": "Entrega completa de SDLC em engenharia web, tecnologia educacional e operações de mídia digital.",
      "2022 - Present": "2022 - Presente",
      "Founder and Lead Developer, Wireless Computer Services": "Fundador e desenvolvedor líder, Wireless Computer Services",
      "Designed and deployed 20+ enterprise-grade applications for school, banking, corporate, and government clients.": "Projetei e implantei mais de 20 aplicações corporativas para escolas, bancos, empresas e governo.",
      "Reduced project timelines by 30% through Laravel backend and Vue plus Tailwind integration.": "Reduzi prazos de projeto em 30% com backend Laravel e integração Vue com Tailwind.",
      "Led end-to-end SDLC: requirements, architecture, implementation, deployment, and maintenance.": "Liderei o SDLC completo: requisitos, arquitetura, implementação, deploy e manutenção.",
      "January 2026 - Present": "Janeiro de 2026 - Presente",
      "Digital and Web Specialist, Glow 99.1 FM (Akure)": "Especialista Digital e Web, Glow 99.1 FM (Akure)",
      "Built and maintain the station website: www.glowfmradio.com.": "Criei e mantenho o site da estação: www.glowfmradio.com.",
      "Manage social media growth, audience engagement, and monetization campaigns.": "Gerencio crescimento em redes sociais, engajamento de audiência e campanhas de monetização.",
      "Execute digital strategy and analytics optimization aligned with station objectives.": "Executo estratégia digital e otimização analítica alinhadas aos objetivos da estação.",
      "Education": "Educação",
      "Key Achievements": "Principais conquistas",
      "Leadership and Interests": "Liderança e interesses",
      "Projects and Portfolio": "Projetos e portfólio",
      "Production platforms across media, education, banking, and developer education.": "Plataformas em produção para mídia, educação, bancos e formação de desenvolvedores.",
      "Media Website": "Site de mídia",
      "School Website": "Site escolar",
      "Bank Website": "Site bancário",
      "Banking Platform": "Plataforma bancária",
      "EdTech Platform": "Plataforma EdTech",
      "Blog and Portfolio": "Blog e portfólio",
      "Client Websites": "Sites de clientes",
      "Visit Website": "Visitar site",
      "What Clients Say": "O que os clientes dizem",
      "Trusted by schools, media brands, and businesses for reliable delivery and clear communication.": "Confiado por escolas, marcas de mídia e empresas por entrega confiável e comunicação clara.",
      "All": "Todos",
      "Media": "Mídia",
      "Education": "Educação",
      "Finance": "Finanças",
      "Corporate": "Corporativo",
      "Book a Call": "Agendar chamada",
      "Let's Discuss Your Project": "Vamos falar sobre seu projeto",
      "Book a 20-minute discovery call to review your goals, timeline, and best technical approach for your website or platform.": "Agende uma chamada de descoberta de 20 minutos para revisar seus objetivos, prazo e a melhor abordagem técnica para seu site ou plataforma.",
      "Book a Call on Calendly": "Agendar no Calendly",
      "Chat on WhatsApp": "Conversar no WhatsApp",
      "Frequently Asked Questions": "Perguntas frequentes",
      "Quick answers to common questions about process, delivery, and collaboration.": "Respostas rápidas sobre processo, entrega e colaboração.",
      "Process": "Processo",
      "Technical": "Técnico",
      "Support": "Suporte",
      "Search question...": "Pesquisar pergunta...",
      "Get In Touch": "Entre em contato",
      "Social Media": "Redes sociais",
      "Send a Message": "Enviar mensagem",
      "Name": "Nome",
      "Subject": "Assunto",
      "Message": "Mensagem",
      "Send Message": "Enviar mensagem",
      "What kind of projects do you handle?": "Que tipo de projetos você realiza?",
      "How long does a typical project take?": "Quanto tempo leva um projeto típico?",
      "Do you work on existing websites?": "Você trabalha em sites existentes?",
      "What technologies do you use?": "Quais tecnologias você usa?",
      "Do you provide maintenance after launch?": "Você oferece manutenção após o lançamento?",
      "How do we start working together?": "Como começamos a trabalhar juntos?",
      "Thanks. Your message was submitted successfully.": "Obrigado. Sua mensagem foi enviada com sucesso."
    }
  };

  const originalTextNodes = new WeakMap();
  const originalAttributes = new WeakMap();
  let currentLanguage = 'en';
  let observer = null;

  function normalizeKey(value) {
    return String(value || '').replace(/\s+/g, ' ').trim();
  }

  function normalizeLanguage(value) {
    if (!value) return null;

    const normalized = String(value).toLowerCase().replace('_', '-').trim();
    const direct = normalized.split('-')[0];
    const aliases = {
      english: 'en',
      spanish: 'es',
      espanol: 'es',
      español: 'es',
      french: 'fr',
      francais: 'fr',
      français: 'fr',
      arabic: 'ar',
      swahili: 'sw',
      kiswahili: 'sw',
      hindi: 'hi',
      hindu: 'hi',
      portuguese: 'pt',
      portugues: 'pt',
      português: 'pt'
    };

    return SUPPORTED_LANGUAGES[normalized]
      ? normalized
      : SUPPORTED_LANGUAGES[direct]
        ? direct
        : aliases[normalized] || aliases[direct] || null;
  }

  function detectLanguageFromTimezone() {
    let timeZone = '';

    try {
      timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    } catch (error) {
      return null;
    }

    const timezoneRules = [
      [/^Asia\/(Riyadh|Dubai|Muscat|Qatar|Bahrain|Kuwait|Baghdad|Amman|Beirut|Damascus|Gaza|Hebron|Aden)$/i, 'ar'],
      [/^Africa\/(Cairo|Tripoli|Khartoum|Algiers|Tunis|Casablanca|El_Aaiun)$/i, 'ar'],
      [/^Africa\/(Nairobi|Dar_es_Salaam|Kampala)$/i, 'sw'],
      [/^Asia\/(Kolkata|Calcutta)$/i, 'hi'],
      [/^Europe\/(Madrid|Andorra)$/i, 'es'],
      [/^Atlantic\/Canary$/i, 'es'],
      [/^America\/(Mexico_City|Bogota|Lima|Santiago|Argentina\/.+|Caracas|La_Paz|Asuncion|Montevideo|Guayaquil|Panama|Costa_Rica|El_Salvador|Guatemala|Havana|Santo_Domingo)$/i, 'es'],
      [/^Europe\/(Paris|Brussels|Monaco|Luxembourg)$/i, 'fr'],
      [/^Europe\/(Lisbon)$/i, 'pt'],
      [/^Atlantic\/(Azores|Madeira|Cape_Verde)$/i, 'pt'],
      [/^America\/(Sao_Paulo|Fortaleza|Recife|Belem|Bahia|Manaus|Porto_Velho|Boa_Vista|Rio_Branco)$/i, 'pt'],
      [/^Africa\/(Luanda|Maputo|Sao_Tome|Bissau)$/i, 'pt']
    ];

    const matchedRule = timezoneRules.find(([pattern]) => pattern.test(timeZone));
    return matchedRule ? matchedRule[1] : null;
  }

  function detectLanguage() {
    const urlLanguage = normalizeLanguage(new URLSearchParams(window.location.search).get('lang'));
    if (urlLanguage) return urlLanguage;

    try {
      const savedLanguage = normalizeLanguage(window.localStorage.getItem(LANGUAGE_STORAGE_KEY));
      if (savedLanguage) return savedLanguage;
    } catch (error) {
      // localStorage may be blocked in private or restricted contexts.
    }

    const browserLanguages = Array.isArray(window.navigator.languages) && window.navigator.languages.length > 0
      ? window.navigator.languages
      : [window.navigator.language];
    const browserLanguage = browserLanguages.map(normalizeLanguage).find(Boolean);

    if (browserLanguage && browserLanguage !== 'en') return browserLanguage;

    return detectLanguageFromTimezone() || browserLanguage || 'en';
  }

  function translate(value, language = currentLanguage) {
    const key = normalizeKey(value);
    if (!key || language === 'en') return key;
    return (TRANSLATIONS[language] && TRANSLATIONS[language][key]) || key;
  }

  function shouldSkipNode(node) {
    const element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    if (!element) return true;
    return Boolean(element.closest('script, style, noscript, svg, [data-no-i18n]'));
  }

  function translateTextNode(node) {
    if (!node.nodeValue || shouldSkipNode(node)) return;

    if (!originalTextNodes.has(node)) {
      originalTextNodes.set(node, node.nodeValue);
    }

    const original = originalTextNodes.get(node);
    const key = normalizeKey(original);
    if (!key) return;

    const translated = translate(key);
    if (currentLanguage === 'en' || translated === key) {
      node.nodeValue = original;
      return;
    }

    const leadingWhitespace = original.match(/^\s*/)[0];
    const trailingWhitespace = original.match(/\s*$/)[0];
    node.nodeValue = `${leadingWhitespace}${translated}${trailingWhitespace}`;
  }

  function translateAttribute(element, attributeName) {
    if (!element.hasAttribute(attributeName) || shouldSkipNode(element)) return;

    let attributeMap = originalAttributes.get(element);
    if (!attributeMap) {
      attributeMap = {};
      originalAttributes.set(element, attributeMap);
    }

    if (!Object.prototype.hasOwnProperty.call(attributeMap, attributeName)) {
      attributeMap[attributeName] = element.getAttribute(attributeName);
    }

    const original = attributeMap[attributeName];
    const translated = translate(original);
    element.setAttribute(attributeName, currentLanguage === 'en' || translated === normalizeKey(original) ? original : translated);
  }

  function translateTree(root = document.body) {
    if (!root) return;

    if (root.nodeType === Node.TEXT_NODE) {
      translateTextNode(root);
      return;
    }

    if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_NODE) return;

    if (root.nodeType === Node.ELEMENT_NODE) {
      ['aria-label', 'alt', 'placeholder', 'title', 'value'].forEach((attributeName) => {
        translateAttribute(root, attributeName);
      });
    }

    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
      acceptNode(node) {
        return shouldSkipNode(node) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
      }
    });

    let node = walker.nextNode();
    while (node) {
      if (node.nodeType === Node.TEXT_NODE) {
        translateTextNode(node);
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        ['aria-label', 'alt', 'placeholder', 'title', 'value'].forEach((attributeName) => {
          translateAttribute(node, attributeName);
        });
      }

      node = walker.nextNode();
    }
  }

  function updateMeta(language) {
    const meta = META[language] || META.en;
    document.documentElement.lang = language;
    document.documentElement.dir = SUPPORTED_LANGUAGES[language].dir;
    document.title = meta.title;

    const metaSelectors = {
      'meta[name="description"]': meta.description,
      'meta[property="og:title"]': meta.title,
      'meta[property="og:description"]': meta.ogDescription,
      'meta[property="og:locale"]': SUPPORTED_LANGUAGES[language].locale,
      'meta[property="og:image:alt"]': meta.imageAlt,
      'meta[name="twitter:title"]': meta.title,
      'meta[name="twitter:description"]': meta.twitterDescription,
      'meta[name="twitter:image:alt"]': meta.imageAlt
    };

    Object.entries(metaSelectors).forEach(([selector, content]) => {
      const element = document.querySelector(selector);
      if (element) element.setAttribute('content', content);
    });
  }

  function syncLanguageControls() {
    document.querySelectorAll('[data-language-select]').forEach((control) => {
      control.value = currentLanguage;

      if (control.dataset.i18nBound === 'true') return;

      control.dataset.i18nBound = 'true';
      control.addEventListener('change', (event) => {
        setLanguage(event.target.value, { persist: true, updateUrl: true });
      });
    });
  }

  function updateUrlLanguage(language) {
    const url = new URL(window.location.href);
    if (language === 'en') {
      url.searchParams.delete('lang');
    } else {
      url.searchParams.set('lang', language);
    }

    window.history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash}`);
  }

  function setLanguage(language, options = {}) {
    const normalizedLanguage = normalizeLanguage(language) || 'en';
    currentLanguage = normalizedLanguage;

    updateMeta(normalizedLanguage);
    translateTree(document.body);
    syncLanguageControls();

    if (options.persist) {
      try {
        window.localStorage.setItem(LANGUAGE_STORAGE_KEY, normalizedLanguage);
      } catch (error) {
        // Ignore localStorage failures.
      }
    }

    if (options.updateUrl) {
      updateUrlLanguage(normalizedLanguage);
    }

    window.dispatchEvent(new CustomEvent('wireless-language-change', {
      detail: { language: normalizedLanguage }
    }));
  }

  function startObserver() {
    if (observer || !document.body) return;

    observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => translateTree(node));
      });
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  function init() {
    setLanguage(detectLanguage(), { persist: Boolean(new URLSearchParams(window.location.search).get('lang')), updateUrl: false });
    startObserver();
  }

  window.WirelessI18n = {
    languages: SUPPORTED_LANGUAGES,
    setLanguage,
    translate,
    getLanguage() {
      return currentLanguage;
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
