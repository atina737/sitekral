// Sorgu Sistemi JavaScript
document.addEventListener('DOMContentLoaded', function() {
    const CSRF = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || window.csrfToken;
    const form = document.getElementById('modalSearchForm');
    const searchBtn = document.getElementById('modalSearchBtn');
    const searchSpinner = document.getElementById('modalSearchSpinner');
    const formSection = document.getElementById('formSection');
    const resultsSection = document.getElementById('resultsSection');
    const resultsBody = document.getElementById('resultsBody');
    const resultCount = document.getElementById('resultCount');
    const noResults = document.getElementById('noResults');
    const exportBtn = document.getElementById('exportBtn');
    const backToFormBtn = document.getElementById('backToFormBtn');
    const modalTitle = document.getElementById('modalTitle');
    const tableSearch = document.getElementById('tableSearch');
    const paginationContainer = document.getElementById('paginationContainer');
    const pagination = document.getElementById('pagination');
    const userQueryCredits = document.getElementById('userQueryCredits');

    // TC Modal elements
    const tcForm = document.getElementById('tcModalSearchForm');
    const tcSearchBtn = document.getElementById('tcModalSearchBtn');
    const tcSearchSpinner = document.getElementById('tcModalSearchSpinner');
    const tcFormSection = document.getElementById('tcFormSection');
    const tcResultsSection = document.getElementById('tcResultsSection');
    const tcResultsBody = document.getElementById('tcResultsBody');
    const tcResultCount = document.getElementById('tcResultCount');
    const tcNoResults = document.getElementById('tcNoResults');
    const tcBackToFormBtn = document.getElementById('tcBackToFormBtn');
    const tcModalTitle = document.getElementById('tcModalTitle');

    // TC → GSM Modal elements
    const tcgsmForm = document.getElementById('tcgsmModalSearchForm');
    const tcgsmSearchBtn = document.getElementById('tcgsmModalSearchBtn');
    const tcgsmSearchSpinner = document.getElementById('tcgsmModalSearchSpinner');
    const tcgsmFormSection = document.getElementById('tcgsmFormSection');
    const tcgsmResultsSection = document.getElementById('tcgsmResultsSection');
    const tcgsmResultsBody = document.getElementById('tcgsmResultsBody');
    const tcgsmResultCount = document.getElementById('tcgsmResultCount');
    const tcgsmNoResults = document.getElementById('tcgsmNoResults');
    const tcgsmBackToFormBtn = document.getElementById('tcgsmBackToFormBtn');
    const tcgsmModalTitle = document.getElementById('tcgsmModalTitle');

    // GSM → TC Modal elements
    const gsmtcForm = document.getElementById('gsmtcModalSearchForm');
    const gsmtcSearchBtn = document.getElementById('gsmtcModalSearchBtn');
    const gsmtcSearchSpinner = document.getElementById('gsmtcModalSearchSpinner');
    const gsmtcFormSection = document.getElementById('gsmtcFormSection');
    const gsmtcResultsSection = document.getElementById('gsmtcResultsSection');
    const gsmtcResultsBody = document.getElementById('gsmtcResultsBody');
    const gsmtcResultCount = document.getElementById('gsmtcResultCount');
    const gsmtcNoResults = document.getElementById('gsmtcNoResults');
    const gsmtcBackToFormBtn = document.getElementById('gsmtcBackToFormBtn');
    const gsmtcModalTitle = document.getElementById('gsmtcModalTitle');

    // Adres Modal elements
    const adresForm = document.getElementById('adresModalSearchForm');
    const adresSearchBtn = document.getElementById('adresModalSearchBtn');
    const adresSearchSpinner = document.getElementById('adresModalSearchSpinner');
    const adresFormSection = document.getElementById('adresFormSection');
    const adresResultsSection = document.getElementById('adresResultsSection');
    const adresResultsBody = document.getElementById('adresResultsBody');
    const adresResultCount = document.getElementById('adresResultCount');
    const adresNoResults = document.getElementById('adresNoResults');
    const adresBackToFormBtn = document.getElementById('adresBackToFormBtn');
    const adresModalTitle = document.getElementById('adresModalTitle');

    // Aile Pro Modal elements
    const aileproForm = document.getElementById('aileproModalSearchForm');
    const aileproSearchBtn = document.getElementById('aileproModalSearchBtn');
    const aileproSearchSpinner = document.getElementById('aileproModalSearchSpinner');
    const aileproFormSection = document.getElementById('aileproFormSection');
    const aileproResultsSection = document.getElementById('aileproResultsSection');
    const aileproResultsBody = document.getElementById('aileproResultsBody');
    const aileproResultCount = document.getElementById('aileproResultCount');
    const aileproNoResults = document.getElementById('aileproNoResults');
    const aileproBackToFormBtn = document.getElementById('aileproBackToFormBtn');
    const aileproModalTitle = document.getElementById('aileproModalTitle');

    // Sülale Modal elements
    const sulaleForm = document.getElementById('sulaleModalSearchForm');
    const sulaleSearchBtn = document.getElementById('sulaleModalSearchBtn');
    const sulaleSearchSpinner = document.getElementById('sulaleModalSearchSpinner');
    const sulaleFormSection = document.getElementById('sulaleFormSection');
    const sulaleResultsSection = document.getElementById('sulaleResultsSection');
    const sulaleResultsBody = document.getElementById('sulaleResultsBody');
    const sulaleResultCount = document.getElementById('sulaleResultCount');
    const sulaleNoResults = document.getElementById('sulaleNoResults');
    const sulaleBackToFormBtn = document.getElementById('sulaleBackToFormBtn');
    const sulaleModalTitle = document.getElementById('sulaleModalTitle');

    // Tapu Modal elements
    const tapuForm = document.getElementById('tapuModalSearchForm');
    const tapuSearchBtn = document.getElementById('tapuModalSearchBtn');
    const tapuSearchSpinner = document.getElementById('tapuModalSearchSpinner');
    const tapuFormSection = document.getElementById('tapuFormSection');
    const tapuResultsSection = document.getElementById('tapuResultsSection');
    const tapuResultsBody = document.getElementById('tapuResultsBody');
    const tapuResultCount = document.getElementById('tapuResultCount');
    const tapuNoResults = document.getElementById('tapuNoResults');
    const tapuBackToFormBtn = document.getElementById('tapuBackToFormBtn');
    const tapuModalTitle = document.getElementById('tapuModalTitle');

    // İş Yeri Modal elements
    const isyeriForm = document.getElementById('isyeriModalSearchForm');
    const isyeriSearchBtn = document.getElementById('isyeriModalSearchBtn');
    const isyeriSearchSpinner = document.getElementById('isyeriModalSearchSpinner');
    const isyeriFormSection = document.getElementById('isyeriFormSection');
    const isyeriResultsSection = document.getElementById('isyeriResultsSection');
    const isyeriResultsBody = document.getElementById('isyeriResultsBody');
    const isyeriResultCount = document.getElementById('isyeriResultCount');
    const isyeriNoResults = document.getElementById('isyeriNoResults');
    const isyeriBackToFormBtn = document.getElementById('isyeriBackToFormBtn');
    const isyeriModalTitle = document.getElementById('isyeriModalTitle');

    // Toastr System
    function showAlert(message, type = 'success') {
        const alertClass = type === 'danger' ? 'alert-danger' : 
                          type === 'warning' ? 'alert-warning' : 
                          type === 'error' ? 'alert-danger' : 'alert-success';
        
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert ${alertClass} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(alertDiv);
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }

    // Pagination variables
    const PAGE_SIZE = 20;
    let currentPage = 1;
    let allData = [];
    let allRows = [];

    // Load user query credits
    async function loadUserCredits() {
        try {
            const response = await fetch('/api/users/info?email=' + encodeURIComponent(window.userEmail || ''), {
                credentials: 'same-origin'
            });
            const data = await response.json();
            if (data.ok && userQueryCredits) {
                userQueryCredits.textContent = `Hak Sayısı: ${data.queryCredits || 0}`;
            }
        } catch (error) {
            console.error('Sorgu hakkı yüklenemedi:', error);
            if (userQueryCredits) {
                userQueryCredits.textContent = 'Hak Sayısı: 0';
            }
        }
    }

    // Update query credits display
    function updateQueryCredits(credits) {
        if (userQueryCredits) {
            userQueryCredits.textContent = `Hak Sayısı: ${credits}`;
        }
    }

    function setLoading(loading) {
        if (searchBtn) {
            searchBtn.disabled = loading;
            if (loading) {
                if (searchSpinner) searchSpinner.classList.remove('d-none');
                searchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
                searchBtn.style.transform = 'scale(0.98)';
                searchBtn.style.boxShadow = '0 4px 15px rgba(102, 126, 234, 0.3)';
            } else {
                if (searchSpinner) searchSpinner.classList.add('d-none');
                searchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
                searchBtn.style.transform = 'scale(1)';
                searchBtn.style.boxShadow = '0 8px 25px rgba(102, 126, 234, 0.4)';
            }
        }
    }

    function showToast(message, type = 'info') {
        showAlert(message, type);
    }

    function formatDate(dateStr) {
        if (!dateStr) return '-';
        try {
            return new Date(dateStr).toLocaleDateString('tr-TR');
        } catch {
            return dateStr;
        }
    }

    function showForm() {
        if (formSection) formSection.style.display = 'block';
        if (resultsSection) resultsSection.style.display = 'none';
        if (modalTitle) modalTitle.textContent = 'Ad Soyad Sorgu';
        
        if (formSection) {
            formSection.style.opacity = '0';
            formSection.style.transform = 'translateY(20px)';
            setTimeout(() => {
                formSection.style.transition = 'all 0.5s ease';
                formSection.style.opacity = '1';
                formSection.style.transform = 'translateY(0)';
            }, 50);
        }
    }

    // TC Modal functions
    function setTcLoading(loading) {
        if (tcSearchBtn) {
            tcSearchBtn.disabled = loading;
            if (loading) {
                if (tcSearchSpinner) tcSearchSpinner.classList.remove('d-none');
                tcSearchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
                tcSearchBtn.style.transform = 'scale(0.98)';
                tcSearchBtn.style.boxShadow = '0 4px 15px rgba(102, 126, 234, 0.3)';
            } else {
                if (tcSearchSpinner) tcSearchSpinner.classList.add('d-none');
                tcSearchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
                tcSearchBtn.style.transform = 'scale(1)';
                tcSearchBtn.style.boxShadow = '0 8px 25px rgba(102, 126, 234, 0.4)';
            }
        }
    }

    function showTcForm() {
        if (tcFormSection) tcFormSection.style.display = 'block';
        if (tcResultsSection) tcResultsSection.style.display = 'none';
        if (tcModalTitle) tcModalTitle.textContent = 'TC Sorgu';
        
        if (tcFormSection) {
            tcFormSection.style.opacity = '0';
            tcFormSection.style.transform = 'translateY(20px)';
            setTimeout(() => {
                tcFormSection.style.transition = 'all 0.5s ease';
                tcFormSection.style.opacity = '1';
                tcFormSection.style.transform = 'translateY(0)';
            }, 50);
        }
    }

    function showTcResults() {
        if (tcFormSection) tcFormSection.style.display = 'none';
        if (tcResultsSection) tcResultsSection.style.display = 'block';
        if (tcModalTitle) tcModalTitle.textContent = 'Sorgu Sonuçları';
        
        if (tcResultsSection) {
            tcResultsSection.style.opacity = '0';
            tcResultsSection.style.transform = 'translateY(20px)';
            setTimeout(() => {
                tcResultsSection.style.transition = 'all 0.5s ease';
                tcResultsSection.style.opacity = '1';
                tcResultsSection.style.transform = 'translateY(0)';
            }, 50);
        }
    }

    function renderTcResults(data) {
        if (!tcResultsBody) return;
        
        if (!data || data.length === 0) {
            tcResultsBody.innerHTML = '';
            if (tcNoResults) tcNoResults.style.display = 'block';
            if (tcResultCount) tcResultCount.textContent = '0 sonuç';
            return;
        }

        if (tcNoResults) tcNoResults.style.display = 'none';
        if (tcResultCount) tcResultCount.textContent = `${data.length} sonuç bulundu`;

        tcResultsBody.innerHTML = data.map((person, index) => `
            <div class="result-item mb-3 p-3 rounded-3 border-0 animate__animated animate__fadeInUp shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); animation-delay: ${index * 0.05}s; backdrop-filter: blur(10px);">
                <div class="d-flex align-items-center justify-content-between mb-3">
                    <div class="d-flex align-items-center gap-3">
                        <span class="badge bg-primary text-white rounded-pill px-3 py-2 shadow-sm" style="font-size: 0.8rem; font-weight: 700; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;">
                            #${index + 1}
                        </span>
                        <div>
                            <h6 class="text-white fw-bold mb-0" style="font-size: 1.1rem;">${person.AD || ''} ${person.SOYAD || ''}</h6>
                            <small class="text-muted">
                                <i class="ti ti-map-pin me-1"></i>${person.DogumYeri || ''}
                            </small>
                        </div>
                    </div>
                    <span class="badge ${person.CINSIYET === 'Erkek' ? 'bg-primary-subtle text-primary' : 'bg-pink-subtle text-pink'} fw-semibold shadow-sm" style="font-size: 0.8rem; padding: 0.5rem 0.8rem; border-radius: 20px;">
                        <i class="ti ti-${person.CINSIYET === 'Erkek' ? 'gender-male' : 'gender-female'} me-1"></i>
                        ${person.CINSIYET || ''}
                    </span>
                </div>
                
                <div class="row g-1">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #667eea;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-id me-2 text-primary"></i>TC Kimlik:
                            </span>
                            <span class="badge bg-primary-subtle text-primary fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-id me-1"></i>${person.TC || '-'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-phone me-2 text-success"></i>GSM:
                            </span>
                            <span class="badge bg-success-subtle text-success fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-phone me-1"></i>${person.GSM || 'YOK'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user-check me-2 text-warning"></i>Baba Adı:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${person.BABAADI || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user-heart me-2 text-danger"></i>Anne Adı:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${person.ANNEADI || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #ffc107;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-calendar me-2 text-warning"></i>Doğum Tarihi:
                            </span>
                            <span class="badge bg-warning-subtle text-warning fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-calendar me-1"></i>${person.DOGUMTARIHI || '-'}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }

    // TC → GSM Modal functions
    function setTcgsmLoading(loading) {
        if (tcgsmSearchBtn) {
            tcgsmSearchBtn.disabled = loading;
            if (loading) {
                if (tcgsmSearchSpinner) tcgsmSearchSpinner.classList.remove('d-none');
                tcgsmSearchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
            } else {
                if (tcgsmSearchSpinner) tcgsmSearchSpinner.classList.add('d-none');
                tcgsmSearchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
            }
        }
    }

    function showTcgsmForm() {
        if (tcgsmFormSection) tcgsmFormSection.style.display = 'block';
        if (tcgsmResultsSection) tcgsmResultsSection.style.display = 'none';
        if (tcgsmModalTitle) tcgsmModalTitle.textContent = 'TC → GSM Sorgu';
    }

    function showTcgsmResults() {
        if (tcgsmFormSection) tcgsmFormSection.style.display = 'none';
        if (tcgsmResultsSection) tcgsmResultsSection.style.display = 'block';
        if (tcgsmModalTitle) tcgsmModalTitle.textContent = 'Sorgu Sonuçları';
    }

    function renderTcgsmResults(data) {
        if (!tcgsmResultsBody) return;
        
        if (!data || data.length === 0) {
            tcgsmResultsBody.innerHTML = '';
            if (tcgsmNoResults) tcgsmNoResults.style.display = 'block';
            if (tcgsmResultCount) tcgsmResultCount.textContent = '0 sonuç';
            return;
        }

        if (tcgsmNoResults) tcgsmNoResults.style.display = 'none';
        if (tcgsmResultCount) tcgsmResultCount.textContent = `${data.length} numara bulundu`;

        tcgsmResultsBody.innerHTML = data.map((item, index) => `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <div class="d-flex align-items-center justify-content-between">
                    <div class="d-flex align-items-center gap-3">
                        <span class="badge bg-success text-white rounded-pill px-3 py-2 shadow-sm" style="font-size: 0.8rem; font-weight: 700;">
                            #${index + 1}
                        </span>
                        <div>
                            <h6 class="text-white fw-bold mb-0">${item.GSM || 'N/A'}</h6>
                            <small class="text-muted">TC: ${item.TC || 'N/A'}</small>
                        </div>
                    </div>
                    <span class="badge bg-primary-subtle text-primary fw-semibold shadow-sm" style="font-size: 0.8rem; padding: 0.5rem 0.8rem; border-radius: 20px;">
                        <i class="ti ti-phone me-1"></i>GSM
                    </span>
                </div>
            </div>
        `).join('');
    }

    // GSM → TC Modal functions
    function setGsmtcLoading(loading) {
        if (gsmtcSearchBtn) {
            gsmtcSearchBtn.disabled = loading;
            if (loading) {
                if (gsmtcSearchSpinner) gsmtcSearchSpinner.classList.remove('d-none');
                gsmtcSearchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
            } else {
                if (gsmtcSearchSpinner) gsmtcSearchSpinner.classList.add('d-none');
                gsmtcSearchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
            }
        }
    }

    function showGsmtcForm() {
        if (gsmtcFormSection) gsmtcFormSection.style.display = 'block';
        if (gsmtcResultsSection) gsmtcResultsSection.style.display = 'none';
        if (gsmtcModalTitle) gsmtcModalTitle.textContent = 'GSM → TC Sorgu';
    }

    function showGsmtcResults() {
        if (gsmtcFormSection) gsmtcFormSection.style.display = 'none';
        if (gsmtcResultsSection) gsmtcResultsSection.style.display = 'block';
        if (gsmtcModalTitle) gsmtcModalTitle.textContent = 'Sorgu Sonuçları';
    }

    function renderGsmtcResults(data) {
        if (!gsmtcResultsBody) return;
        
        if (!data || data.length === 0) {
            gsmtcResultsBody.innerHTML = '';
            if (gsmtcNoResults) gsmtcNoResults.style.display = 'block';
            if (gsmtcResultCount) gsmtcResultCount.textContent = '0 sonuç';
            return;
        }

        if (gsmtcNoResults) gsmtcNoResults.style.display = 'none';
        if (gsmtcResultCount) gsmtcResultCount.textContent = `${data.length} kayıt bulundu`;

        gsmtcResultsBody.innerHTML = data.map((item, index) => `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <div class="d-flex align-items-center justify-content-between">
                    <div class="d-flex align-items-center gap-3">
                        <span class="badge bg-info text-white rounded-pill px-3 py-2 shadow-sm" style="font-size: 0.8rem; font-weight: 700;">
                            #${index + 1}
                        </span>
                        <div>
                            <h6 class="text-white fw-bold mb-0">TC: ${item.TC || 'N/A'}</h6>
                            <small class="text-muted">GSM: ${item.GSM || 'N/A'}</small>
                        </div>
                    </div>
                    <span class="badge bg-info-subtle text-info fw-semibold shadow-sm" style="font-size: 0.8rem; padding: 0.5rem 0.8rem; border-radius: 20px;">
                        <i class="ti ti-id me-1"></i>TC
                    </span>
                </div>
            </div>
        `).join('');
    }

    // Adres Modal functions
    function setAdresLoading(loading) {
        if (adresSearchBtn) {
            adresSearchBtn.disabled = loading;
            if (loading) {
                if (adresSearchSpinner) adresSearchSpinner.classList.remove('d-none');
                adresSearchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
            } else {
                if (adresSearchSpinner) adresSearchSpinner.classList.add('d-none');
                adresSearchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
            }
        }
    }

    function showAdresForm() {
        if (adresFormSection) adresFormSection.style.display = 'block';
        if (adresResultsSection) adresResultsSection.style.display = 'none';
        if (adresModalTitle) adresModalTitle.textContent = 'Adres Sorgu';
    }

    function showAdresResults() {
        if (adresFormSection) adresFormSection.style.display = 'none';
        if (adresResultsSection) adresResultsSection.style.display = 'block';
        if (adresModalTitle) adresModalTitle.textContent = 'Sorgu Sonuçları';
    }

    function renderAdresResults(data) {
        if (!adresResultsBody) return;
        
        if (!data || data.length === 0) {
            adresResultsBody.innerHTML = '';
            if (adresNoResults) adresNoResults.style.display = 'block';
            if (adresResultCount) adresResultCount.textContent = '0 sonuç';
            return;
        }

        if (adresNoResults) adresNoResults.style.display = 'none';
        if (adresResultCount) adresResultCount.textContent = `${data.length} adres bulundu`;

        adresResultsBody.innerHTML = data.map((item, index) => `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <div class="d-flex align-items-center justify-content-between mb-3">
                    <div class="d-flex align-items-center gap-3">
                        <span class="badge bg-warning text-white rounded-pill px-3 py-2 shadow-sm" style="font-size: 0.8rem; font-weight: 700;">
                            #${index + 1}
                        </span>
                        <div>
                            <h6 class="text-white fw-bold mb-0">${item.ad_soyad || 'N/A'}</h6>
                            <small class="text-muted">TC: ${item.tc || 'N/A'}</small>
                        </div>
                    </div>
                    <span class="badge bg-warning-subtle text-warning fw-semibold shadow-sm" style="font-size: 0.8rem; padding: 0.5rem 0.8rem; border-radius: 20px;">
                        <i class="ti ti-map-pin me-1"></i>Adres
                    </span>
                </div>
                <div class="row g-1">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-map me-2 text-warning"></i>Adres:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${item.adres || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-building me-2 text-info"></i>İl:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${item.nufus_il || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-building-community me-2 text-info"></i>İlçe:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${item.nufus_ilce || '-'}</span>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }

    // Aile Pro Modal functions
    function setAileproLoading(loading) {
        if (aileproSearchBtn) {
            aileproSearchBtn.disabled = loading;
            if (loading) {
                if (aileproSearchSpinner) aileproSearchSpinner.classList.remove('d-none');
                aileproSearchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
            } else {
                if (aileproSearchSpinner) aileproSearchSpinner.classList.add('d-none');
                aileproSearchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
            }
        }
    }

    function setSulaleLoading(loading) {
        if (sulaleSearchBtn) {
            sulaleSearchBtn.disabled = loading;
            if (loading) {
                if (sulaleSearchSpinner) sulaleSearchSpinner.classList.remove('d-none');
                sulaleSearchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
            } else {
                if (sulaleSearchSpinner) sulaleSearchSpinner.classList.add('d-none');
                sulaleSearchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
            }
        }
    }

    function setTapuLoading(loading) {
        if (tapuSearchBtn) {
            tapuSearchBtn.disabled = loading;
            if (loading) {
                if (tapuSearchSpinner) tapuSearchSpinner.classList.remove('d-none');
                tapuSearchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
            } else {
                if (tapuSearchSpinner) tapuSearchSpinner.classList.add('d-none');
                tapuSearchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
            }
        }
    }

    function setIsyeriLoading(loading) {
        if (isyeriSearchBtn) {
            isyeriSearchBtn.disabled = loading;
            if (loading) {
                if (isyeriSearchSpinner) isyeriSearchSpinner.classList.remove('d-none');
                isyeriSearchBtn.innerHTML = '<span class="position-relative z-1"><span class="spinner-border spinner-border-sm me-2"></span>Arıyor...</span>';
            } else {
                if (isyeriSearchSpinner) isyeriSearchSpinner.classList.add('d-none');
                isyeriSearchBtn.innerHTML = '<span class="position-relative z-1"><i class="ti ti-search me-2"></i>Sorgula</span>';
            }
        }
    }

    function showAileproForm() {
        if (aileproFormSection) aileproFormSection.style.display = 'block';
        if (aileproResultsSection) aileproResultsSection.style.display = 'none';
        if (aileproModalTitle) aileproModalTitle.textContent = 'Aile Pro Sorgu';
    }

    function showAileproResults() {
        if (aileproFormSection) aileproFormSection.style.display = 'none';
        if (aileproResultsSection) aileproResultsSection.style.display = 'block';
        if (aileproModalTitle) aileproModalTitle.textContent = 'Aile Bilgileri';
    }

    function showSulaleForm() {
        if (sulaleFormSection) sulaleFormSection.style.display = 'block';
        if (sulaleResultsSection) sulaleResultsSection.style.display = 'none';
        if (sulaleModalTitle) sulaleModalTitle.textContent = 'Sülale Sorgu';
    }

    function showSulaleResults() {
        if (sulaleFormSection) sulaleFormSection.style.display = 'none';
        if (sulaleResultsSection) sulaleResultsSection.style.display = 'block';
        if (sulaleModalTitle) sulaleModalTitle.textContent = 'Sülale Sonuçları';
    }

    function showTapuForm() {
        if (tapuFormSection) tapuFormSection.style.display = 'block';
        if (tapuResultsSection) tapuResultsSection.style.display = 'none';
        if (tapuModalTitle) tapuModalTitle.textContent = 'Tapu Sorgu';
    }

    function showTapuResults() {
        if (tapuFormSection) tapuFormSection.style.display = 'none';
        if (tapuResultsSection) tapuResultsSection.style.display = 'block';
        if (tapuModalTitle) tapuModalTitle.textContent = 'Tapu Sonuçları';
    }

    function showIsyeriForm() {
        if (isyeriFormSection) isyeriFormSection.style.display = 'block';
        if (isyeriResultsSection) isyeriResultsSection.style.display = 'none';
        if (isyeriModalTitle) isyeriModalTitle.textContent = 'İş Yeri Sorgu';
    }

    function showIsyeriResults() {
        if (isyeriFormSection) isyeriFormSection.style.display = 'none';
        if (isyeriResultsSection) isyeriResultsSection.style.display = 'block';
        if (isyeriModalTitle) isyeriModalTitle.textContent = 'İş Yeri Sonuçları';
    }

    function renderAileproResults(data) {
        if (!aileproResultsBody) return;
        
        if (!data || !data.veri) {
            aileproResultsBody.innerHTML = '';
            if (aileproNoResults) aileproNoResults.style.display = 'block';
            if (aileproResultCount) aileproResultCount.textContent = '0 sonuç';
            return;
        }

        if (aileproNoResults) aileproNoResults.style.display = 'none';
        if (aileproResultCount) aileproResultCount.textContent = 'Aile bilgileri bulundu';

        const person = data.veri;
        const aile = data.aile || [];
        const cocuklar = data.cocuklar || [];
        const esler = data.esler || [];

        aileproResultsBody.innerHTML = `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <h6 class="text-white fw-bold mb-3">Ana Kişi</h6>
                <div class="row g-1">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05);">
                            <span class="text-muted fw-semibold">Ad Soyad:</span>
                            <span class="text-white fw-bold">${person.AD || ''} ${person.SOYAD || ''}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold">TC:</span>
                            <span class="text-white fw-bold">${person.TC || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold">GSM:</span>
                            <span class="text-white fw-bold">${person.GSM || '-'}</span>
                        </div>
                    </div>
                </div>
            </div>
            
            ${aile.length > 0 ? `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <h6 class="text-white fw-bold mb-3">Aile Üyeleri (${aile.length})</h6>
                ${aile.map((member, index) => `
                    <div class="mb-2 p-2 rounded" style="background: rgba(255,255,255,0.05);">
                        <div class="d-flex justify-content-between">
                            <span class="text-white">${member.AD || ''} ${member.SOYAD || ''} (<span class="text-muted">${member.TC || ''}</span>)</span>
                            
                            
                            <span class="text-muted">${member.CINSIYET || ''}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
            ` : ''}
            
            ${cocuklar.length > 0 ? `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <h6 class="text-white fw-bold mb-3">Çocuklar (${cocuklar.length})</h6>
                ${cocuklar.map((child, index) => `
                    <div class="mb-2 p-2 rounded" style="background: rgba(255,255,255,0.05);">
                        <div class="d-flex justify-content-between">
                            <span class="text-white">${child.AD || ''} ${child.SOYAD || ''} (<span class="text-muted">${child.TC || ''}</span>)</span>
                            <span class="text-muted">${child.CINSIYET || ''}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
            ` : ''}
            
            ${esler.length > 0 ? `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <h6 class="text-white fw-bold mb-3">Eşler (${esler.length})</h6>
                ${esler.map((spouse, index) => `
                    <div class="mb-2 p-2 rounded" style="background: rgba(255,255,255,0.05);">
                        <div class="d-flex justify-content-between">
                            <span class="text-white">${spouse.AD || ''} ${spouse.SOYAD || ''} (<span class="text-muted">${spouse.TC || ''}</span>)</span>
                            <span class="text-muted">${spouse.CINSIYET || ''}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
            ` : ''}
        `;
    }

    function renderSulaleResults(data) {
        if (!sulaleResultsBody) return;
        
        if (!data || data.length === 0) {
            sulaleResultsBody.innerHTML = '';
            if (sulaleNoResults) sulaleNoResults.style.display = 'block';
            if (sulaleResultCount) sulaleResultCount.textContent = '0 sonuç';
            return;
        }

        if (sulaleNoResults) sulaleNoResults.style.display = 'none';
        if (sulaleResultCount) sulaleResultCount.textContent = `${data.length} sülale üyesi bulundu`;

        sulaleResultsBody.innerHTML = data.map((member, index) => `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <div class="d-flex align-items-center mb-3">
                    <div class="result-icon me-3">
                        <i class="ti ti-user-group text-warning"></i>
                    </div>
                    <div>
                        <h4 class="mb-1 text-white">${member.YAKINLIK || ''}</h4>
                    </div>
                </div>
                <div class="row g-1">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #667eea;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-id me-2 text-primary"></i>TC Kimlik:
                            </span>
                            <span class="badge bg-primary-subtle text-primary fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-id me-1"></i>${member.TC || '-'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user me-2 text-info"></i>Ad:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${member.ADI || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user me-2 text-info"></i>Soyad:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${member.SOYADI || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user-check me-2 text-warning"></i>Baba Adı:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${member.BABAADI || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user-heart me-2 text-danger"></i>Anne Adı:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${member.ANNEADI || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #ffc107;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-calendar me-2 text-warning"></i>Doğum Tarihi:
                            </span>
                            <span class="badge bg-warning-subtle text-warning fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-calendar me-1"></i>${member.DOGUMTARIHI || '-'}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }

    function renderTapuResults(data) {
        if (!tapuResultsBody) return;
        
        if (!data) {
            tapuResultsBody.innerHTML = '';
            if (tapuNoResults) tapuNoResults.style.display = 'block';
            if (tapuResultCount) tapuResultCount.textContent = '0 sonuç';
            return;
        }

        if (tapuNoResults) tapuNoResults.style.display = 'none';
        if (tapuResultCount) tapuResultCount.textContent = 'Tapu bilgileri bulundu';

        tapuResultsBody.innerHTML = `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <div class="d-flex align-items-center mb-3">
                    <div class="result-icon me-3">
                        <i class="ti ti-home text-warning"></i>
                    </div>
                    <div>
                        <h6 class="mb-1 text-white">Tapu Bilgileri</h6>
                        <small class="text-muted">Tapu Kayıt No: ${data.Id || '-'}</small>
                    </div>
                </div>
                <div class="row g-1">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #667eea;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-id me-2 text-primary"></i>Tapu Kayıt No:
                            </span>
                            <span class="badge bg-primary-subtle text-primary fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-id me-1"></i>${data.Id || '-'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-map-pin me-2 text-info"></i>İl:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${data.İlBilgisi || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-map-pin me-2 text-info"></i>İlçe:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${data.İlceBilgisi || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #28a745;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-home me-2 text-success"></i>Mahalle:
                            </span>
                            <span class="badge bg-success-subtle text-success fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-home me-1"></i>${data.MahalleBilgisi || 'YOK'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-road me-2 text-warning"></i>Ada:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${data.AdaBilgisi || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-building me-2 text-danger"></i>Parsel:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${data.ParselBilgisi || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #ffc107;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-door me-2 text-warning"></i>Yüzölçümü:
                            </span>
                            <span class="badge bg-warning-subtle text-warning fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-door me-1"></i>${data.YuzolcumBilgisi || '-'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user me-2 text-info"></i>Mal Sahibi:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${data.Name || ''} ${data.Surname || ''}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-id me-2 text-primary"></i>TC Kimlik:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${data.Identify || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #28a745;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-home me-2 text-success"></i>Nitelik:
                            </span>
                            <span class="badge bg-success-subtle text-success fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-home me-1"></i>${data.AnaTasinmazNitelik || '-'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-calendar me-2 text-warning"></i>Tapu Tarihi:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${data.TapuDate || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-file-text me-2 text-info"></i>Edinme Sebebi:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${data.EdinmeSebebi || '-'}</span>
                        </div>
                    </div>
                </div>
            </div>
        `
    }

    function renderIsyeriResults(data) {
        if (!isyeriResultsBody) return;
        
        if (!data || data.length === 0) {
            isyeriResultsBody.innerHTML = '';
            if (isyeriNoResults) isyeriNoResults.style.display = 'block';
            if (isyeriResultCount) isyeriResultCount.textContent = '0 sonuç';
            return;
        }

        if (isyeriNoResults) isyeriNoResults.style.display = 'none';
        if (isyeriResultCount) isyeriResultCount.textContent = `${data.length} iş yeri kaydı bulundu`;

        isyeriResultsBody.innerHTML = data.map((workplace, index) => `
            <div class="result-item mb-3 p-3 rounded-3 border-0 shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); backdrop-filter: blur(10px);">
                <div class="d-flex align-items-center mb-3">
                    <div class="result-icon me-3">
                        <i class="ti ti-building text-info"></i>
                    </div>
                    <div>
                        <h6 class="mb-1 text-white">${workplace.isyeriUnvani || 'İş Yeri'}</h6>
                        <small class="text-muted">SGK No: ${workplace.isyeriSgkSicilNo || '-'}</small>
                    </div>
                </div>
                <div class="row g-1">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #667eea;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-id me-2 text-primary"></i>SGK No:
                            </span>
                            <span class="badge bg-primary-subtle text-primary fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-id me-1"></i>${workplace.isyeriSgkSicilNo || '-'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-building me-2 text-info"></i>İş Yeri Adı:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${workplace.isyeriUnvani || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-map-pin me-2 text-info"></i>İl:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${workplace.il || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #28a745;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-map-pin me-2 text-success"></i>İlçe:
                            </span>
                            <span class="badge bg-success-subtle text-success fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-map-pin me-1"></i>${workplace.ilce || 'YOK'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-calendar me-2 text-warning"></i>Başlangıç Tarihi:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${workplace.iseGirisTarihi || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-calendar me-2 text-danger"></i>Çalışma Durumu:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${workplace.calismaDurumu || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #ffc107;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-briefcase me-2 text-warning"></i>Sektör:
                            </span>
                            <span class="badge bg-warning-subtle text-warning fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-briefcase me-1"></i>${workplace.isyeriSektoru || '-'}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    }

    function showResults() {
        if (formSection) formSection.style.display = 'none';
        if (resultsSection) resultsSection.style.display = 'block';
        if (modalTitle) modalTitle.textContent = 'Sorgu Sonuçları';
        
        if (resultsSection) {
            resultsSection.style.opacity = '0';
            resultsSection.style.transform = 'translateY(20px)';
            setTimeout(() => {
                resultsSection.style.transition = 'all 0.5s ease';
                resultsSection.style.opacity = '1';
                resultsSection.style.transform = 'translateY(0)';
            }, 50);
        }
    }

    function getFiltered() {
        const q = (tableSearch?.value || '').toLowerCase().trim();
        if (!q) return allRows;
        return allRows.filter(item => {
            const name = (item.getAttribute('data-name') || '').toLowerCase();
            const tc = (item.getAttribute('data-tc') || '').toLowerCase();
            const gsm = (item.getAttribute('data-gsm') || '').toLowerCase();
            const baba = (item.getAttribute('data-baba') || '').toLowerCase();
            const anne = (item.getAttribute('data-anne') || '').toLowerCase();
            const dogum = (item.getAttribute('data-dogum') || '').toLowerCase();
            const allText = item.textContent.toLowerCase();
            
            return name.includes(q) || tc.includes(q) || gsm.includes(q) || 
                   baba.includes(q) || anne.includes(q) || dogum.includes(q) ||
                   allText.includes(q);
        });
    }

    function syncPagination(total) {
        if (!pagination) return;
        const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        pagination.innerHTML = '';
        
        const prevLi = document.createElement('li');
        prevLi.className = 'page-item' + (currentPage === 1 ? ' disabled' : '');
        prevLi.innerHTML = `<a href="#" class="page-link border-0 ${currentPage === 1 ? 'bg-secondary text-muted' : 'bg-primary text-white'}" data-page="prev" style="border-radius: 8px; margin: 0 2px; padding: 0.4rem 0.6rem; font-size: 0.8rem;"><i class="ti ti-chevron-left"></i></a>`;
        pagination.appendChild(prevLi);
        
        let startPage = currentPage;
        let endPage = Math.min(totalPages, currentPage + 3);
        
        if (endPage - startPage < 3) {
            startPage = Math.max(1, endPage - 3);
        }
        
        for (let p = startPage; p <= endPage; p++) {
            const li = document.createElement('li');
            li.className = 'page-item' + (p === currentPage ? ' active' : '');
            li.innerHTML = `<a href="#" class="page-link border-0 ${p === currentPage ? 'bg-primary text-white' : 'bg-transparent text-white border-secondary'}" data-page="${p}" style="border-radius: 8px; margin: 0 2px; padding: 0.4rem 0.6rem; font-size: 0.8rem; min-width: 35px;">${p}</a>`;
            pagination.appendChild(li);
        }
        
        const nextLi = document.createElement('li');
        nextLi.className = 'page-item' + (currentPage === totalPages ? ' disabled' : '');
        nextLi.innerHTML = `<a href="#" class="page-link border-0 ${currentPage === totalPages ? 'bg-secondary text-muted' : 'bg-primary text-white'}" data-page="next" style="border-radius: 8px; margin: 0 2px; padding: 0.4rem 0.6rem; font-size: 0.8rem;"><i class="ti ti-chevron-right"></i></a>`;
        pagination.appendChild(nextLi);
    }

    function render() {
        const rows = getFiltered();
        const total = rows.length;
        const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        if (currentPage > totalPages) currentPage = totalPages;
        const start = (currentPage - 1) * PAGE_SIZE;
        const end = start + PAGE_SIZE;
        
        allRows.forEach(item => item.style.display = 'none');
        rows.slice(start, end).forEach(item => item.style.display = 'block');
        
        if (resultCount) resultCount.textContent = total + ' sonuç';
        
        if (total > PAGE_SIZE) {
            if (paginationContainer) paginationContainer.style.display = 'flex';
            syncPagination(total);
        } else {
            if (paginationContainer) paginationContainer.style.display = 'none';
        }
        
        if (total === 0) {
            if (noResults) noResults.style.display = 'block';
        } else {
            if (noResults) noResults.style.display = 'none';
        }
    }

    function renderResults(data) {
        if (!resultsBody) return;
        
        if (!data || data.length === 0) {
            resultsBody.innerHTML = '';
            allRows = [];
            if (noResults) noResults.style.display = 'block';
            if (resultCount) resultCount.textContent = '0 sonuç';
            if (exportBtn) exportBtn.style.display = 'none';
            if (paginationContainer) paginationContainer.style.display = 'none';
            return;
        }

        allData = [...data];
        currentPage = 1;

        if (noResults) noResults.style.display = 'none';
        if (exportBtn) exportBtn.style.display = 'inline-block';

        resultsBody.innerHTML = data.map((person, index) => `
            <div class="result-item mb-3 p-3 rounded-3 border-0 animate__animated animate__fadeInUp shadow-sm" style="background: linear-gradient(135deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.03) 100%); border: 1px solid rgba(255,255,255,0.15); animation-delay: ${index * 0.05}s; backdrop-filter: blur(10px);"
                data-name="${(person.AD || '') + ' ' + (person.SOYAD || '')}"
                data-tc="${person.TC || ''}"
                data-gsm="${person.GSM || ''}"
                data-baba="${person.BABAADI || ''}"
                data-anne="${person.ANNEADI || ''}"
                data-dogum="${person.DOGUMYERI || ''}">
                
                <div class="d-flex align-items-center justify-content-between mb-3">
                    <div class="d-flex align-items-center gap-3">
                        <span class="badge bg-primary text-white rounded-pill px-3 py-2 shadow-sm" style="font-size: 0.8rem; font-weight: 700; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;">
                            #${index + 1}
                        </span>
                        <div>
                            <h6 class="text-white fw-bold mb-0" style="font-size: 1.1rem;">${person.AD || ''} ${person.SOYAD || ''}</h6>
                            <small class="text-muted">
                                <i class="ti ti-map-pin me-1"></i>${person.DOGUMYERI || ''}
                            </small>
                        </div>
                    </div>
                    <span class="badge ${person.CINSIYET === 'E' ? 'bg-primary-subtle text-primary' : 'bg-pink-subtle text-pink'} fw-semibold shadow-sm" style="font-size: 0.8rem; padding: 0.5rem 0.8rem; border-radius: 20px;">
                        <i class="ti ti-${person.CINSIYET === 'E' ? 'gender-male' : 'gender-female'} me-1"></i>
                        ${person.CINSIYET === 'E' ? 'Erkek' : 'Kadın'}
                    </span>
                </div>
                
                <div class="row g-1">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #667eea;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-id me-2 text-primary"></i>TC Kimlik:
                            </span>
                            <span class="badge bg-primary-subtle text-primary fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-id me-1"></i>${person.TC || '-'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user me-2 text-info"></i>Ad:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${person.AD || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user me-2 text-info"></i>Soyad:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${person.SOYAD || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #28a745;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-phone me-2 text-success"></i>GSM:
                            </span>
                            <span class="badge bg-success-subtle text-success fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-phone me-1"></i>${person.GSM || 'YOK'}
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user-check me-2 text-warning"></i>Baba Adı:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${person.BABAADI || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.03);">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-user-heart me-2 text-danger"></i>Anne Adı:
                            </span>
                            <span class="text-white fw-bold" style="font-size: 0.9rem;">${person.ANNEADI || '-'}</span>
                        </div>
                    </div>
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center py-2 px-3 rounded-2" style="background: rgba(255,255,255,0.05); border-left: 3px solid #ffc107;">
                            <span class="text-muted fw-semibold d-flex align-items-center">
                                <i class="ti ti-calendar me-2 text-warning"></i>Doğum Tarihi:
                            </span>
                            <span class="badge bg-warning-subtle text-warning fw-bold shadow-sm" style="font-size: 0.85rem; padding: 0.4rem 0.8rem; border-radius: 15px;">
                                <i class="ti ti-calendar me-1"></i>${person.DOGUMTARIHI || '-'}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');

        allRows = Array.from(resultsBody.querySelectorAll('.result-item'));
        render();
    }

    // Event Listeners
    if (form) {
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const ad = document.getElementById('ad').value.trim();
            const soyad = document.getElementById('soyad').value.trim();
            const il = document.getElementById('il').value.trim();
            
            if (!ad || !soyad) {
                showToast('Ad ve soyad alanları zorunludur!', 'warning');
                return;
            }

            setLoading(true);

            try {
                const response = await fetch('/api/adsoyad', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ ad, soyad, il })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderResults(result.data);
                    showResults();
                    showToast(`${result.data.length} sonuç bulundu`, 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderResults([]);
                    showResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('Search error:', error);
                renderResults([]);
                showResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setLoading(false);
            }
        });
    }

    if (backToFormBtn) {
        backToFormBtn.addEventListener('click', function() {
            showForm();
        });
    }

    if (pagination) {
        pagination.addEventListener('click', function(e) {
            const a = e.target.closest('a.page-link');
            if (!a) return;
            e.preventDefault();
            const target = a.getAttribute('data-page');
            const rows = getFiltered();
            const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
            if (target === 'prev' && currentPage > 1) currentPage--;
            else if (target === 'next' && currentPage < totalPages) currentPage++;
            else if (!isNaN(Number(target))) currentPage = Number(target);
            render();
        });
    }

    if (tableSearch) {
        tableSearch.addEventListener('input', function() { 
            currentPage = 1; 
            render(); 
        });
    }

    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            const table = document.getElementById('resultsTable');
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            
            if (rows.length === 0) {
                showToast('Dışa aktarılacak veri yok', 'warning');
                return;
            }

            let csv = 'TC,Ad Soyad,GSM,Baba Adı,Anne Adı,Doğum Tarihi,Doğum Yeri,Adres,Medeni Hal,Cinsiyet\n';
            
            rows.forEach(row => {
                const cells = Array.from(row.querySelectorAll('td'));
                const rowData = cells.map(cell => {
                    const text = cell.textContent.trim();
                    return `"${text.replace(/"/g, '""')}"`;
                });
                csv += rowData.join(',') + '\n';
            });

            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', `adsoyad-sonuclari-${new Date().toISOString().split('T')[0]}.csv`);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            showToast('Veriler dışa aktarıldı', 'success');
        });
    }

    // TC Form event listener
    if (tcForm) {
        tcForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const tc = document.getElementById('tc').value.trim();
            
            if (!tc) {
                showToast('TC kimlik numarası zorunludur!', 'warning');
                return;
            }

            if (!/^\d{11}$/.test(tc)) {
                showToast('Geçerli bir TC kimlik numarası giriniz (11 haneli)', 'warning');
                return;
            }

            setTcLoading(true);

            try {
                const response = await fetch('/api/tcpro', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ tc })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderTcResults(result.data);
                    showTcResults();
                    showToast(`${result.data.length} sonuç bulundu`, 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderTcResults([]);
                    showTcResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('TC Search error:', error);
                renderTcResults([]);
                showTcResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setTcLoading(false);
            }
        });
    }

    if (tcBackToFormBtn) {
        tcBackToFormBtn.addEventListener('click', function() {
            showTcForm();
        });
    }

    // TC → GSM Form event listener
    if (tcgsmForm) {
        tcgsmForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const tc = document.getElementById('tcgsm').value.trim();
            
            if (!tc) {
                showToast('TC kimlik numarası zorunludur!', 'warning');
                return;
            }

            if (!/^\d{11}$/.test(tc)) {
                showToast('Geçerli bir TC kimlik numarası giriniz (11 haneli)', 'warning');
                return;
            }

            setTcgsmLoading(true);

            try {
                const response = await fetch('/api/tcgsm', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ tc })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderTcgsmResults(result.data);
                    showTcgsmResults();
                    showToast(`${result.data.length} numara bulundu`, 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderTcgsmResults([]);
                    showTcgsmResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('TC → GSM Search error:', error);
                renderTcgsmResults([]);
                showTcgsmResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setTcgsmLoading(false);
            }
        });
    }

    if (tcgsmBackToFormBtn) {
        tcgsmBackToFormBtn.addEventListener('click', function() {
            showTcgsmForm();
        });
    }

    // GSM → TC Form event listener
    if (gsmtcForm) {
        gsmtcForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const gsm = document.getElementById('gsmtc').value.trim();
            
            if (!gsm) {
                showToast('GSM numarası zorunludur!', 'warning');
                return;
            }

            if (!/^\d{10}$/.test(gsm)) {
                showToast('Geçerli bir GSM numarası giriniz (10 haneli)', 'warning');
                return;
            }

            setGsmtcLoading(true);

            try {
                const response = await fetch('/api/gsmtc', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ gsm })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderGsmtcResults(result.data);
                    showGsmtcResults();
                    showToast(`${result.data.length} kayıt bulundu`, 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderGsmtcResults([]);
                    showGsmtcResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('GSM → TC Search error:', error);
                renderGsmtcResults([]);
                showGsmtcResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setGsmtcLoading(false);
            }
        });
    }

    if (gsmtcBackToFormBtn) {
        gsmtcBackToFormBtn.addEventListener('click', function() {
            showGsmtcForm();
        });
    }

    // Adres Form event listener
    if (adresForm) {
        adresForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const tc = document.getElementById('adres').value.trim();
            
            if (!tc) {
                showToast('TC kimlik numarası zorunludur!', 'warning');
                return;
            }

            if (!/^\d{11}$/.test(tc)) {
                showToast('Geçerli bir TC kimlik numarası giriniz (11 haneli)', 'warning');
                return;
            }

            setAdresLoading(true);

            try {
                const response = await fetch('/api/adres', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ tc })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderAdresResults(result.data);
                    showAdresResults();
                    showToast(`${result.data.length} adres bulundu`, 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderAdresResults([]);
                    showAdresResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('Adres Search error:', error);
                renderAdresResults([]);
                showAdresResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setAdresLoading(false);
            }
        });
    }

    if (adresBackToFormBtn) {
        adresBackToFormBtn.addEventListener('click', function() {
            showAdresForm();
        });
    }

    // Aile Pro Form event listener
    if (aileproForm) {
        aileproForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const tc = document.getElementById('ailepro').value.trim();
            
            if (!tc) {
                showToast('TC kimlik numarası zorunludur!', 'warning');
                return;
            }

            if (!/^\d{11}$/.test(tc)) {
                showToast('Geçerli bir TC kimlik numarası giriniz (11 haneli)', 'warning');
                return;
            }

            setAileproLoading(true);

            try {
                const response = await fetch('/api/ailepro', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ tc })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderAileproResults(result.data);
                    showAileproResults();
                    showToast('Aile bilgileri bulundu', 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderAileproResults(null);
                    showAileproResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('Aile Pro Search error:', error);
                renderAileproResults(null);
                showAileproResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setAileproLoading(false);
            }
        });
    }

    if (aileproBackToFormBtn) {
        aileproBackToFormBtn.addEventListener('click', function() {
            showAileproForm();
        });
    }

    // Sülale Form event listener
    if (sulaleForm) {
        sulaleForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const tc = document.getElementById('sulale').value.trim();
            
            if (!tc) {
                showToast('TC kimlik numarası zorunludur!', 'warning');
                return;
            }

            if (!/^\d{11}$/.test(tc)) {
                showToast('Geçerli bir TC kimlik numarası giriniz (11 haneli)', 'warning');
                return;
            }

            setSulaleLoading(true);

            try {
                const response = await fetch('/api/sulale', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ tc })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderSulaleResults(result.data);
                    showSulaleResults();
                    showToast(`${result.data.length} sülale üyesi bulundu`, 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderSulaleResults([]);
                    showSulaleResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('Sülale Search error:', error);
                renderSulaleResults([]);
                showSulaleResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setSulaleLoading(false);
            }
        });
    }

    if (sulaleBackToFormBtn) {
        sulaleBackToFormBtn.addEventListener('click', function() {
            showSulaleForm();
        });
    }

    // Tapu Form event listener
    if (tapuForm) {
        tapuForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const tc = document.getElementById('tapu').value.trim();
            
            if (!tc) {
                showToast('TC kimlik numarası zorunludur!', 'warning');
                return;
            }

            if (!/^\d{11}$/.test(tc)) {
                showToast('Geçerli bir TC kimlik numarası giriniz (11 haneli)', 'warning');
                return;
            }

            setTapuLoading(true);

            try {
                const response = await fetch('/api/tapu', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ tc })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderTapuResults(result.data);
                    showTapuResults();
                    showToast('Tapu bilgileri bulundu', 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderTapuResults(null);
                    showTapuResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('Tapu Search error:', error);
                renderTapuResults(null);
                showTapuResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setTapuLoading(false);
            }
        });
    }

    if (tapuBackToFormBtn) {
        tapuBackToFormBtn.addEventListener('click', function() {
            showTapuForm();
        });
    }

    // İş Yeri Form event listener
    if (isyeriForm) {
        isyeriForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const tc = document.getElementById('isyeri').value.trim();
            
            if (!tc) {
                showToast('TC kimlik numarası zorunludur!', 'warning');
                return;
            }

            if (!/^\d{11}$/.test(tc)) {
                showToast('Geçerli bir TC kimlik numarası giriniz (11 haneli)', 'warning');
                return;
            }

            setIsyeriLoading(true);

            try {
                const response = await fetch('/api/isyeri', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-csrf-token': CSRF
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ tc })
                });

                const result = await response.json();
                
                if (result.ok && result.data) {
                    renderIsyeriResults(result.data);
                    showIsyeriResults();
                    showToast(`${result.data.length} iş yeri kaydı bulundu`, 'success');
                    if (result.remainingCredits !== undefined) {
                        updateQueryCredits(result.remainingCredits);
                    }
                } else {
                    renderIsyeriResults([]);
                    showIsyeriResults();
                    showToast(result.message || 'Arama sırasında bir hata oluştu', 'error');
                }
            } catch (error) {
                console.error('İş Yeri Search error:', error);
                renderIsyeriResults([]);
                showIsyeriResults();
                showToast('Bağlantı hatası oluştu', 'error');
            } finally {
                setIsyeriLoading(false);
            }
        });
    }

    if (isyeriBackToFormBtn) {
        isyeriBackToFormBtn.addEventListener('click', function() {
            showIsyeriForm();
        });
    }

    // Load user credits on page load
    loadUserCredits();
});
