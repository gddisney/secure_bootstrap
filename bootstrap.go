package secure_bootstrap

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

const (
	AuthPageID   ultimate_db.PageID = 1
	ConfigPageID ultimate_db.PageID = 99
)

type UIConfig struct {
	BrandName    string    `json:"brand_name"`
	Logo         string    `json:"logo"`
	PrimaryColor string    `json:"primary_color"`
	Description  string    `json:"description"`
	Fields       []UIField `json:"fields"`
	Buttons      []UIButton `json:"buttons"`
}

type UIField struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Placeholder string `json:"placeholder"`
}

type UIButton struct {
	Label   string `json:"label"`
	Primary bool   `json:"primary"`
	Type    string `json:"type"`
	OnClick string `json:"onclick"`
}

func DefaultConfig() UIConfig {
	return UIConfig{
		BrandName:    "Secure Bootstrap SSO",
		Logo:         "Identity",
		PrimaryColor: "#1d9bf0",
		Description:  "Authenticate securely using your device's native Passkey.",
		Fields: []UIField{
			{ID: "username", Name: "username", Type: "text", Placeholder: "Enter a Username"},
		},
		Buttons: []UIButton{
			{Label: "Sign In with Passkey", Primary: true, Type: "button", OnClick: "passkeyLogin(document.getElementById('username').value)"},
			{Label: "Register New Passkey", Primary: false, Type: "button", OnClick: "passkeyRegister(document.getElementById('username').value)"},
		},
	}
}

func GenerateDynamicGML(cfg UIConfig) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`html(
    head(
        meta:charset."utf-8"(),
        title("%s - Secure Login"),
        script:src."/auth/webauthn.js"(),
        style(
            rule("body", "background-color: #000", "font-family: -apple-system, BlinkMacSystemFont, sans-serif", "margin: 0"),
            rule(".auth-wrapper", "display: flex", "height: 100vh", "width: 100vw", "align-items: center", "justify-content: center"),
            rule(".auth-box", "width: 100%%", "max-width: 420px", "background: #16181c", "border-radius: 16px", "padding: 40px", "text-align: center", "border: 1px solid #2f3336", "box-sizing: border-box"),
            rule(".auth-logo", "font-size: 36px", "margin-bottom: 20px"),
            rule(".auth-title", "color: white", "margin: 0 0 10px 0", "font-size: 24px"),
            rule(".auth-desc", "color: #71767b", "margin-bottom: 30px", "font-size: 15px", "line-height: 1.5"),
            rule(".auth-input", "width: 100%%", "padding: 16px", "margin-bottom: 20px", "border-radius: 8px", "border: 1px solid #333", "background: #000", "color: white", "box-sizing: border-box"),
            rule(".btn-primary", "background: %s", "color: white", "border: none", "padding: 16px", "border-radius: 9999px", "cursor: pointer", "width: 100%%", "font-size: 16px", "font-weight: bold", "margin-bottom: 15px"),
            rule(".btn-secondary", "background: transparent", "color: #e7e9ea", "border: 1px solid #536471", "padding: 16px", "border-radius: 9999px", "cursor: pointer", "width: 100%%", "font-size: 16px", "font-weight: bold")
        )
    ),
    body(
        div.auth-wrapper(
            div.auth-box(
                div.auth-logo("%s"),
                h2.auth-title("Sign in to %s"),
                p.auth-desc("%s"),
                form:onsubmit."event.preventDefault();"(`,
		cfg.BrandName, cfg.PrimaryColor, cfg.Logo, cfg.BrandName, cfg.Description))

	for _, field := range cfg.Fields {
		sb.WriteString(fmt.Sprintf("\n                    input.auth-input:id.\"%s\":name.\"%s\":type.\"%s\":placeholder.\"%s\"(),",
			field.ID, field.Name, field.Type, field.Placeholder))
	}

	for _, btn := range cfg.Buttons {
		btnClass := ".btn-secondary"
		if btn.Primary {
			btnClass = ".btn-primary"
		}

		onclickStr := ""
		if btn.OnClick != "" {
			onclickStr = fmt.Sprintf(`:onclick."%s"`, btn.OnClick)
		}

		sb.WriteString(fmt.Sprintf("\n                    button%s:type.\"%s\"%s(\"%s\"),",
			btnClass, btn.Type, onclickStr, btn.Label))
	}

	sb.WriteString(`
                )
            )
        )
    )
)`)

	return sb.String()
}

// loginInterceptor wraps the ResponseWriter to safely detect webauthnext's success state
type loginInterceptor struct {
	http.ResponseWriter
	status   int
	username string
}

func (i *loginInterceptor) WriteHeader(code int) {
	if i.status == 0 {
		i.status = code
		// If webauthnext approves the passkey, inject our session cookie BEFORE headers flush
		if code == http.StatusOK {
			http.SetCookie(i.ResponseWriter, &http.Cookie{
				Name:     "session_id",
				Value:    "user_session_" + i.username,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
		}
		i.ResponseWriter.WriteHeader(code)
	}
}

func (i *loginInterceptor) Write(b []byte) (int, error) {
	if i.status == 0 {
		i.WriteHeader(http.StatusOK)
	}
	return i.ResponseWriter.Write(b)
}

// BootstrapAuth binds the dynamic identity provider directly to the router and triggers DBSC on success
func BootstrapAuth(router *secure_network.Router, wa *webauthnext.Provider, meshNode *secure_network.MeshNode, gatewayAddr string) {
	// Route 1: Render dynamic UI
	router.Mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		txn := router.DB.BeginTxn()
		cfgBytes, err := router.DB.Read(ConfigPageID, txn, []byte("ui_settings"))
		router.DB.CommitTxn(txn)

		cfg := DefaultConfig()
		if err == nil && len(cfgBytes) > 0 {
			if parseErr := json.Unmarshal(cfgBytes, &cfg); parseErr != nil {
				cfg = DefaultConfig()
			}
		}

		gmlSyntax := GenerateDynamicGML(cfg)

		os.MkdirAll("views", 0755)
		os.WriteFile("views/dynamic_auth.gml", []byte(gmlSyntax), 0644)

		ctx := &guikit.Context{W: w, R: r, Data: make(map[string]interface{})}
		router.GUIKit.Render(ctx, "views/dynamic_auth")
	})

	// Route 2: Handle the Passkey verification completion & Join Mesh
	router.Mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "Missing username parameter", http.StatusBadRequest)
			return
		}

		interceptor := &loginInterceptor{ResponseWriter: w, username: username}
		wa.FinishLogin(interceptor, r)

		if interceptor.status == http.StatusOK {
			log.Printf("[AUTH] User '%s' verified. Initializing secure overlay tunnel...", username)
			go func() {
				if err := meshNode.Connect(gatewayAddr); err != nil {
					log.Printf("[SECURE_MESH] DBSC Auto-Connect Failed for user %s: %v", username, err)
					return
				}
				log.Printf("[SECURE_MESH] DBSC Secure Tunnel Established successfully for user %s", username)
			}()
		} else {
			log.Printf("[AUTH] Passkey verification failed for %s", username)
		}
	})

	// Route 3: Handle Passkey Registration Completion
	router.Mux.HandleFunc("/auth/register/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "Missing username parameter", http.StatusBadRequest)
			return
		}

		interceptor := &loginInterceptor{ResponseWriter: w, username: username}
		wa.FinishRegistration(interceptor, r)

		if interceptor.status == http.StatusOK {
			log.Printf("[AUTH] User '%s' registered and verified. Initializing secure overlay tunnel...", username)
			go func() {
				if err := meshNode.Connect(gatewayAddr); err != nil {
					log.Printf("[SECURE_MESH] DBSC Auto-Connect Failed for user %s: %v", username, err)
					return
				}
				log.Printf("[SECURE_MESH] DBSC Secure Tunnel Established successfully for user %s", username)
			}()
		} else {
			log.Printf("[AUTH] Passkey registration failed for %s", username)
		}
	})
}

// RequireAuth enforces session integrity based on webauthnext's exact behavior
func RequireAuth(router *secure_network.Router, next func(c *guikit.Context)) func(c *guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}

		user := ""
		if strings.HasPrefix(cookie.Value, "user_session_") {
			user = strings.TrimPrefix(cookie.Value, "user_session_")
		}

		if user == "" {
			http.SetCookie(c.W, &http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}

		c.Data["CurrentUser"] = user
		next(c)
	}
}

// RequirePolicy ensures the user is logged in AND has the required policy permissions
func RequirePolicy(pe *secure_policy.PolicyEngine, action, resource string, next func(c *guikit.Context)) func(c *guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}

		user := ""
		if strings.HasPrefix(cookie.Value, "user_session_") {
			user = strings.TrimPrefix(cookie.Value, "user_session_")
		}

		if user == "" {
			http.SetCookie(c.W, &http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}

		// Evaluate the user's permissions using the Zero-Trust policy engine
		if !pe.Evaluate([]byte(user), action, resource, nil) {
			c.W.WriteHeader(http.StatusForbidden)
			c.W.Write([]byte("403 Forbidden: You do not have the required class or permissions to access this resource."))
			return
		}

		c.Data["CurrentUser"] = user
		next(c)
	}
}

// HandleLogout safely destroys the authentication session and redirects to the login screen
func HandleLogout(c *guikit.Context) {
	http.SetCookie(c.W, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true, 
	})

	c.W.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.W.Header().Set("Pragma", "no-cache")
	c.W.Header().Set("Expires", "0")

	http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
}
