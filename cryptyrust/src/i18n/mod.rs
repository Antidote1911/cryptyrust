//! Interface language.
//!
//! The code keeps its English strings: `tr("Close")` returns the text for the
//! current language, and the English text itself when there is no translation.
//! The language is a process-wide setting so that worker threads report their
//! errors in it too. It stays English unless the GUI changes it, so the CLI
//! is not affected.

mod es;
mod fr;

use arsenic::CoreErr;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    Fr,
    Es,
}

impl Lang {
    pub const ALL: [Self; 3] = [Self::En, Self::Fr, Self::Es];

    /// Name of the language, in that language.
    pub const fn name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Fr => "Français",
            Self::Es => "Español",
        }
    }

    /// Identifier stored in the settings.
    pub const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Fr => "fr",
            Self::Es => "es",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.code() == code)
    }

    /// Language of a locale such as `fr-FR` or `fr_CA.UTF-8`; English when it
    /// is not a supported one.
    pub fn from_locale(locale: &str) -> Self {
        let language = locale.split(['-', '_', '.']).next().unwrap_or("");
        Self::from_code(&language.to_lowercase()).unwrap_or(Self::En)
    }

    /// Language of the operating system session.
    pub fn system() -> Self {
        sys_locale::get_locale().map_or(Self::En, |l| Self::from_locale(&l))
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(lang: Lang) {
    CURRENT.store(
        match lang {
            Lang::En => 0,
            Lang::Fr => 1,
            Lang::Es => 2,
        },
        Ordering::Relaxed,
    );
}

pub fn lang() -> Lang {
    match CURRENT.load(Ordering::Relaxed) {
        1 => Lang::Fr,
        2 => Lang::Es,
        _ => Lang::En,
    }
}

type Table = HashMap<&'static str, &'static str>;

fn french() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| fr::FR.iter().copied().collect())
}

fn spanish() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| es::ES.iter().copied().collect())
}

/// `en` in `lang`; `en` itself when there is no translation.
pub fn tr_in(lang: Lang, en: &str) -> &str {
    let table = match lang {
        Lang::En => return en,
        Lang::Fr => french(),
        Lang::Es => spanish(),
    };
    table.get(en).copied().unwrap_or(en)
}

/// `en` in the current language.
pub fn tr(en: &str) -> &str {
    tr_in(lang(), en)
}

/// Translate `en`, then replace each `{name}` placeholder by its value.
pub fn trf(en: &str, args: &[(&str, &dyn Display)]) -> String {
    fill(tr(en), args)
}

fn fill(template: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut text = template.to_string();
    for (name, value) in args {
        text = text.replace(&format!("{{{name}}}"), &value.to_string());
    }
    text
}

/// Message of a library error in the current language. The detail carried by
/// an error (an I/O message, a reason given by the library) is kept as is.
pub fn core_err(e: &CoreErr) -> String {
    match lang() {
        Lang::En => e.to_string(),
        Lang::Fr => core_err_fr(e),
        Lang::Es => core_err_es(e),
    }
}

fn core_err_fr(e: &CoreErr) -> String {
    match e {
        CoreErr::CreateCipher => {
            "Erreur : impossible de créer le chiffrement avec la clé dérivée par Argon2id.".into()
        }
        CoreErr::Argon2Params => {
            "Erreur : impossible d'initialiser les paramètres Argon2id.".into()
        }
        CoreErr::Argon2Hash => {
            "Erreur : impossible de dériver le mot de passe avec Argon2.".into()
        }
        CoreErr::DecryptionError => {
            "Échec du déchiffrement : mot de passe incorrect ou fichier corrompu.".into()
        }
        CoreErr::ReadError { .. } => "Erreur de lecture".into(),
        CoreErr::IOError(source) => format!("Erreur d'E/S : {source}"),
        CoreErr::DecryptFail(detail) => format!("Échec du déchiffrement : {detail}"),
        CoreErr::DeleteFail(what, why) => format!("{what} Suppression impossible : {why}"),
        CoreErr::EncryptFail(detail) => format!("Échec du chiffrement : {detail}"),
        CoreErr::BadSignature => {
            "Échec du déchiffrement : signature incorrecte. Ce n'est pas un fichier Arsenic valide."
                .into()
        }
        CoreErr::BadHeaderVersion => {
            "Version de format non prise en charge (cette version ne lit que les fichiers Arsenic V2)."
                .into()
        }
        CoreErr::NoAsymKeyFound => {
            "Échec du déchiffrement : aucun emplacement de clé asymétrique ne correspond à la clé privée fournie."
                .into()
        }
        CoreErr::Cancelled => "Opération annulée.".into(),
    }
}

fn core_err_es(e: &CoreErr) -> String {
    match e {
        CoreErr::CreateCipher => {
            "Error: no se pudo crear el cifrado con la clave derivada por Argon2id.".into()
        }
        CoreErr::Argon2Params => {
            "Error: no se pudieron inicializar los parámetros de Argon2id.".into()
        }
        CoreErr::Argon2Hash => "Error: no se pudo derivar la contraseña con Argon2.".into(),
        CoreErr::DecryptionError => {
            "Error de descifrado: contraseña incorrecta o archivo dañado.".into()
        }
        CoreErr::ReadError { .. } => "Error de lectura".into(),
        CoreErr::IOError(source) => format!("Error de E/S: {source}"),
        CoreErr::DecryptFail(detail) => format!("Error de descifrado: {detail}"),
        CoreErr::DeleteFail(what, why) => format!("{what} No se puede eliminar: {why}"),
        CoreErr::EncryptFail(detail) => format!("Error de cifrado: {detail}"),
        CoreErr::BadSignature => {
            "Error de descifrado: firma incorrecta. No es un archivo Arsenic válido.".into()
        }
        CoreErr::BadHeaderVersion => {
            "Versión de formato no compatible (esta versión solo lee archivos Arsenic V2).".into()
        }
        CoreErr::NoAsymKeyFound => {
            "Error de descifrado: ninguna ranura de clave asimétrica corresponde a la clave privada proporcionada."
                .into()
        }
        CoreErr::Cancelled => "Operación cancelada.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholders(text: &str) -> Vec<&str> {
        let mut found: Vec<&str> = text
            .split('{')
            .skip(1)
            .filter_map(|part| part.split_once('}').map(|(name, _)| name))
            .collect();
        found.sort_unstable();
        found
    }

    #[test]
    fn tables_are_consistent() {
        assert_eq!(french().len(), fr::FR.len(), "duplicate English key (fr)");
        assert_eq!(spanish().len(), es::ES.len(), "duplicate English key (es)");
        for (en, text) in fr::FR.iter().chain(es::ES) {
            assert!(!text.is_empty(), "empty translation of {en:?}");
            assert_eq!(placeholders(en), placeholders(text), "placeholders of {en:?}");
            assert_eq!(en.matches('\n').count(), text.matches('\n').count(), "lines of {en:?}");
        }
    }

    /// A text translated into French and missing from the Spanish table is
    /// either identical in Spanish or forgotten: the identical ones are listed.
    #[test]
    fn spanish_covers_the_french_table() {
        const SAME_IN_SPANISH: [&str; 5] = ["General", "B", "KB", "MB", "GB"];
        for (en, _) in fr::FR {
            assert!(
                spanish().contains_key(en) || SAME_IN_SPANISH.contains(en),
                "no Spanish text for {en:?}"
            );
        }
    }

    #[test]
    fn untranslated_text_falls_back_to_english() {
        assert_eq!(tr_in(Lang::En, "Close"), "Close");
        assert_eq!(tr_in(Lang::Fr, "Close"), "Fermer");
        assert_eq!(tr_in(Lang::Es, "Close"), "Cerrar");
        assert_eq!(tr_in(Lang::Fr, "XChaCha20-Poly1305"), "XChaCha20-Poly1305");
    }

    #[test]
    fn placeholders_are_filled() {
        let template = tr_in(Lang::Fr, "A key named \"{name}\" already exists.");
        assert_eq!(fill(template, &[("name", &"alice")]), "Une clé nommée « alice » existe déjà.");
    }

    #[test]
    fn language_is_read_from_locale_and_code() {
        assert_eq!(Lang::from_locale("fr-FR"), Lang::Fr);
        assert_eq!(Lang::from_locale("fr_CA.UTF-8"), Lang::Fr);
        assert_eq!(Lang::from_locale("es-MX"), Lang::Es);
        assert_eq!(Lang::from_locale("en-US"), Lang::En);
        assert_eq!(Lang::from_locale("de-DE"), Lang::En);
        assert_eq!(Lang::from_code("fr"), Some(Lang::Fr));
        assert_eq!(Lang::from_code("xx"), None);
    }
}
