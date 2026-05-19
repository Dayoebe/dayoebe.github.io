(() => {
  const BASE_CURRENCY = 'NGN';
  const CURRENCY_STORAGE_KEY = 'wireless-terminal-currency-v1';
  const RATE_STORAGE_KEY = 'wireless-terminal-currency-rates-v1';
  const RATE_ENDPOINT = 'https://open.er-api.com/v6/latest/NGN';
  const LOCATION_ENDPOINTS = [
    'https://ipwho.is/',
    'https://api.country.is/'
  ];
  const COUNTRY_ENDPOINT = (countryCode) => `https://restcountries.com/v3.1/alpha/${countryCode}?fields=currencies`;

  const DEFAULT_CURRENCIES = [
    { code: 'NGN', label: 'Nigerian naira' },
    { code: 'USD', label: 'US dollar' },
    { code: 'GBP', label: 'British pound' },
    { code: 'EUR', label: 'Euro' },
    { code: 'CAD', label: 'Canadian dollar' },
    { code: 'AUD', label: 'Australian dollar' },
    { code: 'GHS', label: 'Ghanaian cedi' },
    { code: 'KES', label: 'Kenyan shilling' },
    { code: 'ZAR', label: 'South African rand' },
    { code: 'INR', label: 'Indian rupee' },
    { code: 'AED', label: 'UAE dirham' }
  ];

  const FALLBACK_COUNTRY_CURRENCY = {
    NG: 'NGN',
    US: 'USD',
    GB: 'GBP',
    CA: 'CAD',
    AU: 'AUD',
    GH: 'GHS',
    KE: 'KES',
    ZA: 'ZAR',
    IN: 'INR',
    AE: 'AED'
  };

  const EURO_COUNTRIES = new Set([
    'AT', 'BE', 'HR', 'CY', 'EE', 'FI', 'FR', 'DE', 'GR', 'IE', 'IT', 'LV',
    'LT', 'LU', 'MT', 'NL', 'PT', 'SK', 'SI', 'ES'
  ]);

  const state = {
    currency: BASE_CURRENCY,
    rates: { [BASE_CURRENCY]: 1 },
    rateSource: 'fallback',
    selectionSource: 'detecting',
    userSelected: false,
    optionCurrencies: [...DEFAULT_CURRENCIES]
  };

  const translate = (value) => {
    if (window.WirelessI18n && typeof window.WirelessI18n.translate === 'function') {
      return window.WirelessI18n.translate(value);
    }

    return value;
  };

  const withCurrency = (template, currencyCode) => (
    translate(template).replace('{currency}', currencyCode)
  );

  function normalizeCurrency(value) {
    return String(value || '').trim().toUpperCase();
  }

  function getStoredCurrency() {
    try {
      return normalizeCurrency(window.localStorage.getItem(CURRENCY_STORAGE_KEY));
    } catch (error) {
      return '';
    }
  }

  function storeCurrency(currencyCode) {
    try {
      window.localStorage.setItem(CURRENCY_STORAGE_KEY, currencyCode);
    } catch (error) {
      // Ignore localStorage failures.
    }
  }

  function getCachedRates() {
    try {
      const cached = JSON.parse(window.localStorage.getItem(RATE_STORAGE_KEY) || 'null');
      if (!cached || cached.base !== BASE_CURRENCY || !cached.rates) return null;
      return cached;
    } catch (error) {
      return null;
    }
  }

  function storeRates(payload) {
    try {
      window.localStorage.setItem(RATE_STORAGE_KEY, JSON.stringify(payload));
    } catch (error) {
      // Ignore localStorage failures.
    }
  }

  async function fetchJson(url, timeout = 4500) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Request failed: ${response.status}`);
      return await response.json();
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function loadRates() {
    const cached = getCachedRates();

    try {
      const data = await fetchJson(RATE_ENDPOINT, 6000);
      if (data && data.result === 'success' && data.rates && data.rates[BASE_CURRENCY]) {
        const payload = {
          base: BASE_CURRENCY,
          rates: data.rates,
          updatedAt: data.time_last_update_utc || new Date().toISOString()
        };
        storeRates(payload);
        state.rates = payload.rates;
        state.rateSource = 'live';
        return;
      }
    } catch (error) {
      // Cached rates keep the pricing useful when the rate service is unavailable.
    }

    if (cached) {
      state.rates = cached.rates;
      state.rateSource = 'cached';
      return;
    }

    state.rates = { [BASE_CURRENCY]: 1 };
    state.rateSource = 'fallback';
  }

  function countryFromLocale() {
    const language = navigator.languages && navigator.languages.length
      ? navigator.languages[0]
      : navigator.language;

    try {
      return normalizeCurrency(new Intl.Locale(language).region);
    } catch (error) {
      const match = String(language || '').match(/[-_]([A-Za-z]{2})$/);
      return match ? normalizeCurrency(match[1]) : '';
    }
  }

  function fallbackCurrencyForCountry(countryCode) {
    const country = normalizeCurrency(countryCode);
    if (!country) return '';
    if (EURO_COUNTRIES.has(country)) return 'EUR';
    return FALLBACK_COUNTRY_CURRENCY[country] || '';
  }

  async function detectCountry() {
    for (const endpoint of LOCATION_ENDPOINTS) {
      try {
        const data = await fetchJson(endpoint);
        const countryCode = data.country_code || data.country || data.countryCode;
        if (countryCode) return normalizeCurrency(countryCode);
      } catch (error) {
        // Try the next location provider.
      }
    }

    return countryFromLocale();
  }

  async function currencyForCountry(countryCode) {
    const country = normalizeCurrency(countryCode);
    if (!country) return '';

    try {
      const data = await fetchJson(COUNTRY_ENDPOINT(country));
      const countryData = Array.isArray(data) ? data[0] : data;
      const currencies = countryData && countryData.currencies ? Object.keys(countryData.currencies) : [];
      if (currencies.length > 0) return normalizeCurrency(currencies[0]);
    } catch (error) {
      // Fall back to the compact local map below.
    }

    return fallbackCurrencyForCountry(country);
  }

  async function detectCurrency() {
    const country = await detectCountry();
    return currencyForCountry(country);
  }

  function currencyExists(currencyCode) {
    return Boolean(state.rates[currencyCode]);
  }

  function ensureCurrencyOption(currencyCode) {
    const code = normalizeCurrency(currencyCode);
    if (!code || state.optionCurrencies.some((currency) => currency.code === code)) return;

    let label = code;

    try {
      if (typeof Intl.DisplayNames === 'function') {
        const displayNames = new Intl.DisplayNames([document.documentElement.lang || navigator.language || 'en'], { type: 'currency' });
        label = displayNames.of(code) || code;
      }
    } catch (error) {
      label = code;
    }

    state.optionCurrencies.push({ code, label });
  }

  function populateCurrencyControls() {
    const controls = document.querySelectorAll('[data-currency-select]');
    controls.forEach((control) => {
      const selectedValue = control.value || state.currency;
      control.innerHTML = '';

      state.optionCurrencies.forEach((currency) => {
        const option = document.createElement('option');
        option.value = currency.code;
        option.textContent = `${currency.code} - ${currency.label}`;
        control.append(option);
      });

      control.value = state.optionCurrencies.some((currency) => currency.code === selectedValue)
        ? selectedValue
        : state.currency;

      if (control.dataset.currencyBound === 'true') return;

      control.dataset.currencyBound = 'true';
      control.addEventListener('change', (event) => {
        const nextCurrency = normalizeCurrency(event.target.value);
        if (!nextCurrency) return;

        state.currency = nextCurrency;
        state.selectionSource = currencyExists(nextCurrency) || state.rateSource === 'fallback' ? 'manual' : 'unavailable';
        state.userSelected = true;
        storeCurrency(state.currency);
        renderPrices();
      });
    });
  }

  function currentLocale() {
    const pageLanguage = document.documentElement.lang || 'en';
    if (pageLanguage === 'en') return 'en-NG';
    return pageLanguage;
  }

  function formatCurrency(amount, currencyCode) {
    const roundedAmount = Math.round(amount);

    if (currencyCode === BASE_CURRENCY && Math.abs(roundedAmount) >= 1000) {
      const thousands = roundedAmount / 1000;
      const compactAmount = Number.isInteger(thousands)
        ? String(thousands)
        : thousands.toFixed(1).replace(/\.0$/, '');
      return `\u20a6${compactAmount}k`;
    }

    const options = {
      style: 'currency',
      currency: currencyCode,
      maximumFractionDigits: 0
    };

    if (Math.abs(roundedAmount) >= 10000) {
      options.notation = 'compact';
      options.compactDisplay = 'short';
    }

    try {
      return new Intl.NumberFormat(currentLocale(), options).format(roundedAmount);
    } catch (error) {
      return `${currencyCode} ${roundedAmount.toLocaleString()}`;
    }
  }

  function statusText() {
    let primary;

    if (state.selectionSource === 'detected') {
      primary = withCurrency('Using {currency} based on your location.', state.currency);
    } else if (state.selectionSource === 'unavailable') {
      primary = translate('Currency rate unavailable. Showing Nigerian naira.');
    } else if (state.selectionSource === 'detecting') {
      primary = translate('Detecting your local currency...');
    } else {
      primary = withCurrency('Showing {currency}.', state.currency);
    }

    let secondary = translate('Showing Nigerian naira until live rates are available.');
    if (state.rateSource === 'live') secondary = translate('Live exchange rates loaded.');
    if (state.rateSource === 'cached') secondary = translate('Using saved exchange rates while offline.');

    return `${primary} ${secondary}`.trim();
  }

  function renderPrices() {
    const activeCurrency = currencyExists(state.currency) ? state.currency : BASE_CURRENCY;
    const rate = state.rates[activeCurrency] || 1;

    document.querySelectorAll('[data-price]').forEach((element) => {
      const baseAmount = Number(element.dataset.baseAmount || 0);
      const convertedAmount = baseAmount * rate;
      element.textContent = formatCurrency(convertedAmount, activeCurrency);
      element.dataset.currency = activeCurrency;
    });

    document.querySelectorAll('[data-currency-code]').forEach((element) => {
      element.textContent = activeCurrency;
    });

    document.querySelectorAll('[data-currency-status]').forEach((element) => {
      element.textContent = statusText();
    });

    document.querySelectorAll('[data-currency-select]').forEach((control) => {
      control.value = state.optionCurrencies.some((currency) => currency.code === state.currency)
        ? state.currency
        : activeCurrency;
    });
  }

  async function hydrateCurrency() {
    await loadRates();

    const storedCurrency = getStoredCurrency();
    if (storedCurrency && currencyExists(storedCurrency)) {
      ensureCurrencyOption(storedCurrency);
      state.currency = storedCurrency;
      state.selectionSource = 'manual';
      populateCurrencyControls();
      renderPrices();
      return;
    }

    if (state.userSelected) {
      renderPrices();
      return;
    }

    const detectedCurrency = await detectCurrency();
    if (detectedCurrency && currencyExists(detectedCurrency)) {
      ensureCurrencyOption(detectedCurrency);
      state.currency = detectedCurrency;
      state.selectionSource = 'detected';
    } else {
      state.currency = BASE_CURRENCY;
      state.selectionSource = 'manual';
    }

    populateCurrencyControls();
    renderPrices();
  }

  function init() {
    if (!document.querySelector('[data-price]')) return;

    const storedCurrency = getStoredCurrency();
    if (storedCurrency) {
      ensureCurrencyOption(storedCurrency);
      state.currency = storedCurrency;
      state.selectionSource = 'manual';
    }

    populateCurrencyControls();
    renderPrices();
    hydrateCurrency();

    window.addEventListener('wireless-language-change', () => {
      populateCurrencyControls();
      renderPrices();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
