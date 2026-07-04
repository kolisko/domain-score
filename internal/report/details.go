package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kolisko/domain-score/internal/audit"
)

const (
	DetailsOff      = "off"
	DetailsFindings = "findings"
	DetailsAll      = "all"
)

func IsDetailsMode(mode string) bool {
	switch normalizeDetailsMode(mode) {
	case DetailsOff, DetailsFindings, DetailsAll:
		return true
	default:
		return false
	}
}

func normalizeDetailsMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", DetailsOff, "none", "false", "0":
		return DetailsOff
	case DetailsFindings, "finding", "problems", "problem":
		return DetailsFindings
	case DetailsAll, "full", "true", "1":
		return DetailsAll
	default:
		return "invalid"
	}
}

func detailResults(results []audit.Result, sortMode string, detailsMode string, detailsCheck string) []audit.Result {
	results = sortedResults(results, sortMode)
	detailsCheck = strings.TrimSpace(detailsCheck)
	if detailsCheck != "" {
		out := make([]audit.Result, 0, 1)
		for _, res := range results {
			if res.CheckID == detailsCheck {
				out = append(out, res)
			}
		}
		return out
	}
	switch normalizeDetailsMode(detailsMode) {
	case DetailsAll:
		return results
	case DetailsFindings:
		out := make([]audit.Result, 0, len(results))
		for _, res := range results {
			if isFinding(res.Status) {
				out = append(out, res)
			}
		}
		return out
	default:
		return nil
	}
}

func isFinding(status audit.Status) bool {
	return status == audit.StatusFail || status == audit.StatusWarn || status == audit.StatusError
}

func problemText(res audit.Result) string {
	if res.Error != "" {
		return fmt.Sprintf("Check se nepodařilo spolehlivě vyhodnotit: %s", res.Error)
	}
	switch res.Status {
	case audit.StatusPass:
		return "Kontrola prošla; audit našel očekávaný veřejný signál nebo bezpečný stav."
	case audit.StatusWarn:
		if res.Recommendation != "" {
			return "Stav není ideální: " + res.Recommendation
		}
		return "Kontrola našla stav, který stojí za ruční ověření nebo zlepšení."
	case audit.StatusFail:
		if res.Recommendation != "" {
			return "Kontrola selhala: " + res.Recommendation
		}
		return "Kontrola nenašla požadovaný bezpečnostní nebo provozní signál."
	case audit.StatusNotApplicable:
		return "Kontrola pro tuto doménu není použitelná nebo pro ni nebyla dostupná potřebná veřejná data."
	default:
		return "Stav kontroly není jednoznačný."
	}
}

func riskText(res audit.Result) string {
	switch res.CheckID {
	case "dns.dmarc":
		return "Bez DMARC je jednodušší zneužít doménu pro e-mail spoofing a phishing; příjemci nemají jasnou politiku pro zprávy, které neprojdou SPF/DKIM."
	case "dns.spf":
		return "Chybějící nebo slabé SPF zvyšuje riziko spoofingu odesílatelů a zhoršuje doručitelnost legitimních e-mailů."
	case "dns.dkim":
		return "Bez DKIM podpisu příjemce hůř ověřuje, že zpráva nebyla cestou upravena a že ji podepsala infrastruktura domény."
	case "http.hsts":
		return "Bez HSTS se uživatel může při prvním nebo chybně směrovaném HTTP přístupu dostat na nezabezpečenou variantu webu."
	case "http.csp":
		return "Slabá nebo chybějící CSP zvyšuje dopad XSS a injekcí obsahu, protože prohlížeč nemá jasně omezené zdroje skriptů a dat."
	case "http.https_redirect":
		return "Bez vynuceného HTTPS mohou uživatelé nebo integrace skončit na nešifrovaném HTTP spojení."
	case "external.internetdb_cves":
		return "Veřejné zdroje ukazují CVE signály na infrastruktuře spojené s doménou; pokud jsou relevantní, může jít o známé zranitelnosti dostupné z internetu."
	case "reputation.spamhaus_dbl":
		return "Výskyt v reputační databázi může znamenat spam, phishing, malware nebo kompromitovanou reputaci domény a může poškodit doručitelnost i důvěru."
	case "reputation.surbl":
		return "Výskyt v SURBL může znamenat, že doména byla spojena se spamem nebo škodlivými URL."
	case "reputation.urlhaus":
		return "Výskyt v URLhaus je silný signál možného malware nebo phishing zneužití URL spojených s doménou."
	case "tls.certificate_valid":
		return "Neplatný nebo nedostupný TLS certifikát může způsobit blokaci webu v prohlížečích a ztrátu důvěry uživatelů."
	case "tls.expiry":
		return "Blížící se expirace certifikátu může vést k náhlému výpadku HTTPS a chybám v prohlížečích i API klientech."
	}

	switch res.Category {
	case "dns":
		return "DNS nastavení je základ důvěryhodnosti domény; chyby mohou ovlivnit dostupnost, e-mailovou bezpečnost nebo vydávání certifikátů."
	case "tls":
		return "TLS problém může ohrozit důvěru spojení, kompatibilitu klientů nebo dostupnost HTTPS."
	case "http_security":
		return "HTTP bezpečnostní hlavičky snižují dopad běžných webových útoků a pomáhají prohlížeči vynutit bezpečný režim."
	case "seo":
		return "SEO signály pomáhají vyhledávačům správně pochopit, indexovat a zobrazovat obsah domény."
	case "ai_optimization":
		return "AI/model signály pomáhají asistentům a crawlerům správně najít, citovat a interpretovat obsah."
	case "performance":
		return "Výkonové a UX problémy mohou zhoršit použitelnost, konverze i hodnocení ve vyhledávačích."
	case "transparency":
		return "Transparentní kontakty a veřejné záznamy zrychlují řešení bezpečnostních incidentů a zvyšují důvěryhodnost."
	case "reputation":
		return "Reputační nález je často externí signál možného zneužití, kompromitace nebo blokování domény."
	case "external_public":
		return "Externí veřejné zdroje doplňují pohled mimo přímé měření a mohou upozornit na historické nebo pasivně zjištěné problémy."
	case "microsoft_365":
		return "Microsoft 365 signály pomáhají odhalit identitní a e-mailové nastavení, které může ovlivnit bezpečnost tenantů."
	default:
		return "Tento stav může ovlivnit bezpečnost, důvěryhodnost, dostupnost nebo čitelnost veřejné domény."
	}
}

func fixText(res audit.Result) string {
	if res.Recommendation != "" {
		return res.Recommendation
	}
	if res.Status == audit.StatusPass {
		return "Bez nutné akce; udržujte tento stav a zahrňte ho do pravidelného monitoringu."
	}
	if res.Status == audit.StatusNotApplicable {
		return "Bez nutné akce, pokud tato funkce nebo technologie pro doménu nedává smysl."
	}
	return "Ověřte uvedenou evidenci a upravte konfiguraci služby podle doporučeného cílového stavu."
}

func targetStateText(res audit.Result, domain string) string {
	if res.Status == audit.StatusPass {
		return "Současný veřejně zjištěný stav odpovídá cíli; udržujte konfiguraci a pravidelně ji monitorujte."
	}
	switch res.CheckID {
	case "dns.dmarc":
		return fmt.Sprintf("_dmarc.%s TXT \"v=DMARC1; p=none; rua=mailto:dmarc@%s\"; po vyhodnocení reportů postupně přejít na p=quarantine nebo p=reject.", domain, domain)
	case "dns.spf":
		return "Publikovat právě jeden SPF TXT záznam s autorizovanými odesílateli, například `v=spf1 include:_spf.example-provider.tld -all`."
	case "dns.dkim":
		return "Zapnout DKIM u poštovní služby a publikovat odpovídající selector TXT záznamy v DNS."
	case "http.hsts":
		return "`Strict-Transport-Security: max-age=31536000; includeSubDomains`; preload používat až po ověření všech subdomén."
	case "http.csp":
		return "Začít s report-only CSP, odstranit zbytečné `unsafe-inline`, nastavit minimálně `default-src 'self'` a explicitní zdroje pro script/style/img/connect."
	case "http.https_redirect":
		return "Veškeré HTTP požadavky přesměrovat trvalým redirectem na kanonickou HTTPS URL."
	case "external.internetdb_cves":
		return "Potvrdit službu a verzi na dotčeném hostu, ověřit relevanci CVE, aplikovat patch/backport nebo omezit veřejnou dostupnost služby."
	case "reputation.spamhaus_dbl", "reputation.surbl", "reputation.urlhaus":
		return "Prověřit kompromitaci webu/DNS/e-mailů, odstranit škodlivý obsah, zkontrolovat redirecty a požádat příslušný zdroj o delisting."
	}
	if res.Recommendation != "" {
		return res.Recommendation
	}
	return "Cílový stav: check vrací PASS nebo je vědomě označen jako nerelevantní pro danou doménu."
}

func evidenceLines(res audit.Result) []string {
	lines := make([]string, 0, len(res.Evidence)+1)
	if res.Error != "" {
		lines = append(lines, "error: "+res.Error)
	}
	keys := make([]string, 0, len(res.Evidence))
	for key := range res.Evidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s: %s", key, formatEvidenceValue(res.Evidence[key])))
	}
	if len(lines) == 0 {
		return []string{"Konkrétní evidence není u tohoto checku k dispozici; výsledek vychází z nasbíraných veřejných signálů v auditním běhu."}
	}
	return lines
}

func formatEvidenceValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case string:
		if strings.TrimSpace(v) == "" {
			return `""`
		}
		return truncate(v, 180)
	case fmt.Stringer:
		return truncate(v.String(), 180)
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return truncate(fmt.Sprint(v), 180)
		}
		return truncate(string(data), 180)
	}
}
