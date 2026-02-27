/*
 * Plugin: DSD-FME Auto metadata panel
 */

(function () {
  window.Plugins = window.Plugins || {};
  window.Plugins.dsdfme_auto = window.Plugins.dsdfme_auto || {};
  var plugin = window.Plugins.dsdfme_auto;

  function logOnce() {
    if (window.__dsdfmePanelLogOnce) {
      return;
    }
    window.__dsdfmePanelLogOnce = true;
    console.log('DSDFME panel loaded');
  }

  function removeLegacyWatermark() {
    function removeNow() {
      var mark = document.getElementById('dsdfme-loaded-watermark');
      if (mark && mark.parentNode) {
        mark.parentNode.removeChild(mark);
      }
    }

    removeNow();
    setTimeout(removeNow, 25);
    setTimeout(removeNow, 150);
    setTimeout(removeNow, 600);
  }

  function injectPanel() {
    function ensureUserImages($panel) {
      $panel.find('.dsdfme-slot').each(function () {
        var $slot = $(this);
        var $title = $slot.children('.dsdfme-slot-title').first();
        if ($title.length && !$title.next('.dsdfme-user-image').length) {
          $('<div class="dsdfme-user-image" aria-hidden="true"></div>').insertAfter($title);
        }
      });

      $panel.find('.dsdfme-single').each(function () {
        var $single = $(this);
        var $title = $single.children('.dsdfme-single-mode').first();
        if ($title.length && !$title.next('.dsdfme-user-image').length) {
          $('<div class="dsdfme-user-image" aria-hidden="true"></div>').insertAfter($title);
        }
      });
    }

    if (document.getElementById('openwebrx-panel-metadata-dsdfme')) {
      ensureUserImages($('#openwebrx-panel-metadata-dsdfme'));
      return;
    }

    var html =
      '<div class="openwebrx-panel openwebrx-meta-panel dsdfme-mode-dmr" id="openwebrx-panel-metadata-dsdfme" style="display: none;" data-panel-name="metadata-dsdfme">' +
        '<div class="dsdfme-meta-header">' +
          '<span class="dsdfme-title">DSDFME</span>' +
          '<span class="dsdfme-header-right">' +
            '<span class="dsdfme-current-mode">DMR</span>' +
            '<span class="dsdfme-dmr-badge"></span>' +
            '<span class="dsdfme-header-crypto"></span>' +
          '</span>' +
        '</div>' +

        '<div class="dsdfme-dmr-grid">' +
          '<div class="openwebrx-meta-slot dsdfme-slot" data-slot="0">' +
            '<div class="dsdfme-slot-title">TS1</div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">TG</span><span class="dsdfme-slot-tg"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">ID</span><span class="dsdfme-slot-id"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">NAME</span><span class="dsdfme-slot-name"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">CC</span><span class="dsdfme-slot-cc"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">TYPE</span><span class="dsdfme-slot-type"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">MODE</span><span class="dsdfme-slot-simplex"></span></div>' +
            '<div class="dsdfme-row dsdfme-crypto-row"><span class="dsdfme-key">CRYPTO</span><span class="dsdfme-slot-crypto"></span></div>' +
          '</div>' +
          '<div class="openwebrx-meta-slot dsdfme-slot" data-slot="1">' +
            '<div class="dsdfme-slot-title">TS2</div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">TG</span><span class="dsdfme-slot-tg"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">ID</span><span class="dsdfme-slot-id"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">NAME</span><span class="dsdfme-slot-name"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">CC</span><span class="dsdfme-slot-cc"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">TYPE</span><span class="dsdfme-slot-type"></span></div>' +
            '<div class="dsdfme-row"><span class="dsdfme-key">MODE</span><span class="dsdfme-slot-simplex"></span></div>' +
            '<div class="dsdfme-row dsdfme-crypto-row"><span class="dsdfme-key">CRYPTO</span><span class="dsdfme-slot-crypto"></span></div>' +
          '</div>' +
        '</div>' +

        '<div class="openwebrx-meta-slot dsdfme-single">' +
          '<div class="dsdfme-single-mode">MODE</div>' +
          '<div class="dsdfme-row"><span class="dsdfme-key dsdfme-single-label-nac">NAC</span><span class="dsdfme-single-nac"></span></div>' +
          '<div class="dsdfme-row"><span class="dsdfme-key dsdfme-single-label-tg">TG</span><span class="dsdfme-single-tg"></span></div>' +
          '<div class="dsdfme-row"><span class="dsdfme-key dsdfme-single-label-uid">UID</span><span class="dsdfme-single-uid"></span></div>' +
          '<div class="dsdfme-row"><span class="dsdfme-key">NAME</span><span class="dsdfme-single-name"></span></div>' +
          '<div class="dsdfme-row dsdfme-crypto-row"><span class="dsdfme-key">ENC</span><span class="dsdfme-single-crypto"></span></div>' +
        '</div>' +
      '</div>';

    var $panel = $(html);
    var $anchor = $('#openwebrx-panel-metadata-dmr');

    if ($anchor.length) {
      $anchor.after($panel);
      ensureUserImages($panel);
      return;
    }

    var $metaPanels = $('.openwebrx-meta-panel');
    if ($metaPanels.length) {
      $metaPanels.last().after($panel);
      ensureUserImages($panel);
      return;
    }

    $('#openwebrx-panels-container-left').append($panel);
    ensureUserImages($panel);
  }

  function isDsdfmeModulation(m) {
    if (!m) return false;
    m = String(m);
    return m === 'dsdfme' || m === 'dsd-fme-auto' || m.indexOf('dsdfme-') === 0;
  }

  function patchModeAlias() {
    if (typeof Modes === 'undefined' || typeof Modes.findByModulation !== 'function') {
      return;
    }

    var originalFind = Modes.findByModulation;
    if (originalFind.__dsdfmeAliasPatched) {
      return;
    }

    Modes.findByModulation = function (modulation) {
      if (modulation === 'dsd-fme-auto') {
        modulation = 'dsdfme';
      }
      return originalFind.call(this, modulation);
    };

    Modes.findByModulation.__dsdfmeAliasPatched = true;
  }

  function patchPanelVisibility() {
    if (
      typeof DemodulatorPanel === 'undefined' ||
      !DemodulatorPanel.prototype ||
      typeof DemodulatorPanel.prototype.updatePanels !== 'function' ||
      typeof toggle_panel !== 'function'
    ) {
      return false;
    }

    var originalUpdatePanels = DemodulatorPanel.prototype.updatePanels;
    if (originalUpdatePanels.__dsdfmePanelPatched) {
      return true;
    }

    DemodulatorPanel.prototype.updatePanels = function () {
      originalUpdatePanels.apply(this, arguments);

      var demod = this && typeof this.getDemodulator === 'function' ? this.getDemodulator() : null;
      if (!demod || typeof demod.get_modulation !== 'function') {
        return;
      }

      var modulation = demod.get_modulation();
      if (!isDsdfmeModulation(modulation)) {
        return;
      }

      var panel = document.getElementById('openwebrx-panel-metadata-dsdfme');
      if (panel && !panel.classList.contains('disabled')) {
        toggle_panel('openwebrx-panel-metadata-dsdfme', true);
        var panel$ = $('#openwebrx-panel-metadata-dsdfme');
        var metap = panel$.data('metapanel');
        if (metap && typeof metap.hintProfile === 'function') {
          metap.hintProfile(modulation);
        }
      }
    };

    DemodulatorPanel.prototype.updatePanels.__dsdfmePanelPatched = true;
    return true;
  }

  function refreshPanels() {
    try {
      if (typeof UI === 'undefined' || typeof UI.getDemodulatorPanel !== 'function') {
        return;
      }
      var panel = UI.getDemodulatorPanel();
      if (panel && typeof panel.updatePanels === 'function' && panel.getDemodulator && panel.getDemodulator()) {
        panel.updatePanels();
      }
    } catch (e) {
      console.warn('dsdfme_auto: unable to refresh panels', e);
    }
  }

  function DsdfmeMetaPanel(el) {
    MetaPanel.call(this, el);

    this.renderIntervalMs = 100;
    this.highlightTtlMs = 1500;

    this.$header = this.el.find('.dsdfme-meta-header');
    this.$currentMode = this.el.find('.dsdfme-current-mode');
    this.$dmrBadge = this.el.find('.dsdfme-dmr-badge');
    this.$headerCrypto = this.el.find('.dsdfme-header-crypto');

    this.$slots = {
      '0': this._bindSlot('0'),
      '1': this._bindSlot('1')
    };

    this.$single = this.el.find('.dsdfme-single');
    this.$singleMode = this.el.find('.dsdfme-single-mode');
    this.$singleNac = this.el.find('.dsdfme-single-nac');
    this.$singleTg = this.el.find('.dsdfme-single-tg');
    this.$singleUid = this.el.find('.dsdfme-single-uid');
    this.$singleName = this.el.find('.dsdfme-single-name');
    this.$singleCrypto = this.el.find('.dsdfme-single-crypto');
    this.$singleLabelNac = this.el.find('.dsdfme-single-label-nac');
    this.$singleLabelTg = this.el.find('.dsdfme-single-label-tg');
    this.$singleLabelUid = this.el.find('.dsdfme-single-label-uid');

    this.nameCache = new Map();
    this.model = this._emptyModel();
    this.clear();

    this._renderTimer = setInterval(this._render.bind(this), this.renderIntervalMs);
  }

  DsdfmeMetaPanel.prototype = new MetaPanel();

  DsdfmeMetaPanel.prototype._bindSlot = function (slot) {
    var $root = this.el.find('.dsdfme-slot[data-slot="' + slot + '"]');
    return {
      root: $root,
      tg: $root.find('.dsdfme-slot-tg'),
      id: $root.find('.dsdfme-slot-id'),
      name: $root.find('.dsdfme-slot-name'),
      cc: $root.find('.dsdfme-slot-cc'),
      type: $root.find('.dsdfme-slot-type'),
      simplex: $root.find('.dsdfme-slot-simplex'),
      crypto: $root.find('.dsdfme-slot-crypto')
    };
  };

  DsdfmeMetaPanel.prototype._emptySlotState = function () {
    return {
      tg: '',
      id: '',
      name: '',
      cc: '',
      callType: '',
      simplex: false,
      encrypted: false,
      crypto: '',
      activeUntil: 0
    };
  };

  DsdfmeMetaPanel.prototype._emptySingleState = function () {
    return {
      mode: '',
      nac: '',
      tg: '',
      uid: '',
      uidName: '',
      encrypted: false,
      crypto: '',
      activeUntil: 0
    };
  };

  DsdfmeMetaPanel.prototype._emptyModel = function () {
    return {
      mode: 'DMR',
      dmrSimplex: false,
      slots: {
        '0': this._emptySlotState(),
        '1': this._emptySlotState()
      },
      single: this._emptySingleState()
    };
  };

  DsdfmeMetaPanel.prototype.isSupported = function (data) {
    return !!data && data.protocol === 'DSDFME';
  };

  DsdfmeMetaPanel.prototype._normalizeMode = function (mode) {
    var normalized = (mode || '').toString().toUpperCase();
    if (!normalized) {
      return 'DMR';
    }
    if (normalized === 'D-STAR') {
      return 'DSTAR';
    }
    return normalized;
  };

  DsdfmeMetaPanel.prototype._setText = function ($el, value) {
    var text = value || '';
    if ($el.text() !== text) {
      $el.text(text);
    }
  };

  DsdfmeMetaPanel.prototype._valueOrDash = function (value) {
    if (value === undefined || value === null || value === '') {
      return '—';
    }
    return String(value);
  };

  DsdfmeMetaPanel.prototype._setClass = function ($el, className, enabled) {
    if (enabled) {
      if (!$el.hasClass(className)) {
        $el.addClass(className);
      }
    } else if ($el.hasClass(className)) {
      $el.removeClass(className);
    }
  };

  DsdfmeMetaPanel.prototype._cryptoText = function (data) {
    if (data && data.crypto_text) {
      return data.crypto_text;
    }

    var parts = ['ENCRYPTED'];
    if (data && data.algid) {
      parts.push('ALGID=' + data.algid);
    }
    if (data && data.keyid) {
      parts.push('KEYID=' + data.keyid);
    }
    return parts.join(' ');
  };

  DsdfmeMetaPanel.prototype._composeResolvedName = function (callsign, name) {
    if (callsign && name) {
      return callsign + ' — ' + name;
    }
    if (callsign) {
      return callsign;
    }
    if (name) {
      return name;
    }
    return '';
  };

  DsdfmeMetaPanel.prototype._resolveDmrNameFromMeta = function (data) {
    if (!data) {
      return '';
    }
    var callsign = data.callsign ? String(data.callsign) : '';
    var name = data.name ? String(data.name) : '';
    return this._composeResolvedName(callsign, name);
  };

  DsdfmeMetaPanel.prototype.resolveDmrName = function (id, data) {
    var rawId = id !== undefined && id !== null ? String(id) : '';
    if (!rawId) {
      return '';
    }

    if (this.nameCache.has(rawId)) {
      return this.nameCache.get(rawId) || '';
    }

    // DSDFME backend enriches metadata with callsign/name when available.
    var resolved = this._resolveDmrNameFromMeta(data);
    if (resolved) {
      this.nameCache.set(rawId, resolved);
    }
    return resolved || '';
  };

  DsdfmeMetaPanel.prototype._setHeader = function (mode, encrypted, cryptoText) {
    this._setText(this.$currentMode, mode || 'DMR');
    this._setClass(this.$header, 'encrypted', encrypted);
    this._setText(this.$headerCrypto, encrypted ? '\uD83D\uDD12 ' + (cryptoText || 'ENCRYPTED') : '');
  };

  DsdfmeMetaPanel.prototype._setLayout = function (mode) {
    if (mode === 'DMR') {
      this.el.addClass('dsdfme-mode-dmr').removeClass('dsdfme-mode-single');
      this.$dmrBadge.show();
    } else {
      this.el.addClass('dsdfme-mode-single').removeClass('dsdfme-mode-dmr');
      this.$dmrBadge.hide();
    }
  };

  DsdfmeMetaPanel.prototype._ingestDmr = function (data, now) {
    var slot = data && data.slot !== undefined && data.slot !== null ? String(data.slot) : null;

    if (data.clear === true) {
      if (slot === '0' || slot === '1') {
        this.model.slots[slot] = this._emptySlotState();
      } else {
        this.model.slots['0'] = this._emptySlotState();
        this.model.slots['1'] = this._emptySlotState();
      }
      return;
    }

    if (slot !== '0' && slot !== '1') {
      return;
    }

    var st = this.model.slots[slot];

    if (data.tg !== undefined && data.tg !== null && data.tg !== '') {
      st.tg = String(data.tg);
    }

    if (data.id !== undefined && data.id !== null && data.id !== '') {
      var nextId = String(data.id);
      if (st.id !== nextId) {
        st.id = nextId;
        st.name = '';
      }
      var resolved = this.resolveDmrName(st.id, data);
      if (resolved) {
        st.name = resolved;
      }
    }

    if (data.cc !== undefined && data.cc !== null && data.cc !== '') {
      st.cc = String(data.cc);
    }

    if (data.call_type !== undefined && data.call_type !== null && data.call_type !== '') {
      st.callType = String(data.call_type);
    }

    if (data.simplex === true) {
      st.simplex = true;
      this.model.dmrSimplex = true;
    } else if (data.simplex === false) {
      st.simplex = false;
      this.model.dmrSimplex = false;
    }

    if (data.encrypted === true) {
      st.encrypted = true;
      st.crypto = this._cryptoText(data);
    } else if (data.encrypted === false) {
      st.encrypted = false;
      st.crypto = '';
    }

    if (data.sync === 'voice') {
      var otherSlot = slot === '0' ? '1' : '0';
      this.model.slots[otherSlot].activeUntil = 0;
      st.activeUntil = now + this.highlightTtlMs;
    }
  };

  DsdfmeMetaPanel.prototype._ingestSingle = function (data, mode, now) {
    if (data.clear === true) {
      this.model.single = this._emptySingleState();
      this.model.single.mode = mode;
      return;
    }

    var st = this.model.single;
    st.mode = mode;

    if (mode === 'P25') {
      if (data.nac !== undefined && data.nac !== null && data.nac !== '') {
        st.nac = String(data.nac);
      }
      if (data.tg !== undefined && data.tg !== null && data.tg !== '') {
        st.tg = String(data.tg);
      }
      var uidCandidate = null;
      if (data.uid !== undefined && data.uid !== null && data.uid !== '') {
        uidCandidate = data.uid;
      } else if (data.source !== undefined && data.source !== null && data.source !== '') {
        uidCandidate = data.source;
      } else if (data.id !== undefined && data.id !== null && data.id !== '') {
        uidCandidate = data.id;
      }
      if (uidCandidate !== null) {
        var nextUid = String(uidCandidate);
        if (st.uid !== nextUid) {
          st.uid = nextUid;
          st.uidName = '';
        }
        var resolvedUid = this.resolveDmrName(st.uid, data);
        if (resolvedUid) {
          st.uidName = resolvedUid;
        }
      }
    } else {
      if (data.nac !== undefined && data.nac !== null && data.nac !== '') {
        st.nac = String(data.nac);
      }
      if (data.tg !== undefined && data.tg !== null && data.tg !== '') {
        st.tg = String(data.tg);
      }
      if (data.uid !== undefined && data.uid !== null && data.uid !== '') {
        st.uid = String(data.uid);
      }
    }

    if (data.encrypted === true) {
      st.encrypted = true;
      st.crypto = this._cryptoText(data);
    } else if (data.encrypted === false) {
      st.encrypted = false;
      st.crypto = '';
    }

    if (data.sync === 'voice') {
      st.activeUntil = now + this.highlightTtlMs;
    }
  };

  DsdfmeMetaPanel.prototype._renderDmr = function (now) {
    var encryptedText = '';
    var hasEncrypted = false;
    var dmrSimplex = this.model.dmrSimplex === true;

    this._setText(this.$dmrBadge, dmrSimplex ? 'SIMPLEX' : 'REPEATER');
    this._setClass(this.$dmrBadge, 'is-simplex', dmrSimplex);
    this._setClass(this.$dmrBadge, 'is-repeater', !dmrSimplex);

    ['0', '1'].forEach(function (slot) {
      var st = this.model.slots[slot];
      var ui = this.$slots[slot];
      var active = st.activeUntil > now;
      var isGroup = active && /group/i.test(st.callType || '');

      this._setClass(ui.root, 'active', active);
      this._setClass(ui.root, 'sync', active);
      ui.root.toggleClass('group', isGroup);
      this._setClass(ui.root, 'encrypted', active && !!st.encrypted);

      this._setText(ui.tg, active ? this._valueOrDash(st.tg) : '—');
      this._setText(ui.id, active ? this._valueOrDash(st.id) : '—');
      this._setText(ui.name, active && st.name ? st.name : '');
      this._setText(ui.cc, active ? this._valueOrDash(st.cc) : '—');
      this._setText(ui.type, active ? this._valueOrDash(st.callType) : '—');
      this._setText(ui.simplex, active && st.simplex ? 'SIMPLEX' : '—');
      this._setText(ui.crypto, active && st.encrypted ? st.crypto : '');

      if (active && st.encrypted && !hasEncrypted) {
        hasEncrypted = true;
        encryptedText = st.crypto || 'ENCRYPTED';
      }
    }, this);

    this._setHeader('DMR', hasEncrypted, encryptedText);
  };

  DsdfmeMetaPanel.prototype._renderSingle = function (now) {
    var st = this.model.single;
    var mode = this._normalizeMode(st.mode || this.model.mode);
    var active = st.activeUntil > now;
    var singleRoot = this.$single;
    var activeSingle = active;
    if (!activeSingle) {
      var hasTargetOrSource = !!(st.tg || st.uid);
      var idleHint = ((st.tg || '') + ' ' + (st.uid || '')).toString();
      var isIdle = /\bidle\b/i.test(idleHint);
      activeSingle = !!(mode && hasTargetOrSource && !isIdle);
    }
    var isGroupSingle = activeSingle && /group/i.test((this.model.callType || this.model.singleCallType || ''));

    singleRoot.toggleClass('active', !!activeSingle);
    singleRoot.toggleClass('group', !!isGroupSingle);
    this._setClass(this.$single, 'sync', active);
    this._setClass(this.$single, 'encrypted', !!st.encrypted);

    this._setText(this.$singleMode, mode || 'MODE');

    if (mode === 'P25') {
      this._setText(this.$singleLabelNac, 'NAC');
      this._setText(this.$singleLabelTg, 'TG');
      this._setText(this.$singleLabelUid, 'UID');
    } else {
      this._setText(this.$singleLabelNac, 'INFO');
      this._setText(this.$singleLabelTg, 'TG');
      this._setText(this.$singleLabelUid, 'ID');
    }

    this._setText(this.$singleNac, this._valueOrDash(st.nac));
    this._setText(this.$singleTg, this._valueOrDash(st.tg));
    this._setText(this.$singleUid, this._valueOrDash(st.uid));
    this._setText(this.$singleName, mode === 'P25' && st.uidName ? st.uidName : '');
    this._setText(this.$singleCrypto, st.encrypted ? (st.crypto || 'ENCRYPTED') : (mode === 'P25' ? 'CLEAR' : ''));

    this._setHeader(mode, !!st.encrypted, st.crypto || 'ENCRYPTED');
  };

  DsdfmeMetaPanel.prototype._render = function () {
    var now = Date.now();
    var mode = this._normalizeMode(this.model.mode);

    this._setLayout(mode);

    if (mode === 'DMR') {
      this._renderDmr(now);
    } else {
      this._renderSingle(now);
    }
  };

  DsdfmeMetaPanel.prototype.update = function (data) {
    if (!this.isSupported(data)) {
      return;
    }

    var now = Date.now();
    var mode = this._normalizeMode(data.mode || this.model.mode || 'DMR');

    this.model.mode = mode;

    if (mode === 'DMR') {
      this._ingestDmr(data, now);
    } else {
      this._ingestSingle(data, mode, now);
    }
  };

  DsdfmeMetaPanel.prototype.clear = function () {
    MetaPanel.prototype.clear.call(this);
    this.model = this._emptyModel();
    this._render();
  };

  DsdfmeMetaPanel.prototype.hintProfile = function (modulation) {
    modulation = String(modulation || '');
    if (modulation === 'dsdfme-nxdn48' || modulation === 'dsdfme-nxdn96') {
      this.model.mode = 'NXDN';
      this._render();
    } else if (modulation === 'dsdfme-dpmr') {
      this.model.mode = 'DPMR';
      this._render();
    }
  };

  plugin.init = function () {
    if (window.__dsdfmeAutoInitialized) {
      return true;
    }

    if (typeof $ === 'undefined' || typeof MetaPanel === 'undefined') {
      console.error('dsdfme_auto requires jQuery and MetaPanel.');
      return false;
    }

    window.__dsdfmeAutoInitialized = true;

    logOnce();
    removeLegacyWatermark();
    injectPanel();
    patchModeAlias();

    if (!patchPanelVisibility()) {
      var tries = 0;
      var timer = setInterval(function () {
        tries += 1;
        if (patchPanelVisibility() || tries > 30) {
          clearInterval(timer);
        }
      }, 100);
    }

    MetaPanel.types.dsdfme = DsdfmeMetaPanel;
    MetaPanel.types["dsdfme-nxdn48"] = DsdfmeMetaPanel;
    MetaPanel.types["dsdfme-nxdn96"] = DsdfmeMetaPanel;
    MetaPanel.types["dsdfme-dpmr"]   = DsdfmeMetaPanel;
    MetaPanel.types["dsd-fme-auto"]  = DsdfmeMetaPanel;
    $('#openwebrx-panel-metadata-dsdfme').removeData('metapanel').metaPanel();

    refreshPanels();
    setTimeout(refreshPanels, 250);

    return true;
  };

  window.DSDFME_AUTO_INIT = plugin.init;
})();
