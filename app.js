var createError = require('http-errors');
var express = require('express');
const fs = require('fs');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const myPlaintextPassword = 's0/\/\P4$$w0rD';
const someOtherPlaintextPassword = 'not_bacon';
const fileUpload = require('express-fileupload');
var stringSimilarity = require("string-similarity");
var jwt = require('jsonwebtoken');
var nodemailer = require('nodemailer');
var glob = require("glob")
var io = null;

//povezivanje na bazu
const { Pool, Client } = require('pg')
const pool = new Pool({
  user: 'yqeejuyl',
  host: 'abul.db.elephantsql.com',
  database: 'yqeejuyl',
  password: 'J-g27cNqQvkY8jFqvK3lLWX5EJ0XsxT6',
  port: 5432,
  max: 10,
  idleTimeoutMillis: 30000
});

//callback funkcije
var funkcije = {
  vratiKategorije: function (req, res, next) {
    pool.query(`SELECT * from podkategorija;`, async (err, result) => {
      req.podkategorija = await result.rows;
      next();
    });
  },
    vratiArtikle: function (req, res, next) {
        pool.query(`select * from artikal order by id_artikla desc;`, async (err, result) => {
            req.artikli = await result.rows;
            next();
        });
    },
    vratiArtiklePoCijeni: function (req, res, next) {
        pool.query(`select * from artikal order by cijena desc;`, async (err, result) => {
            req.artikliCijena = await result.rows;
            next();
        });
    },
    vratiKorpe: function (req, res, next){
        pool.query(`select * from korpa;`, async (err, result) => {
            req.korpe = await result.rows;
            next();
        });
    },
    vratiPoruke: function (req, res, next) {
        pool.query(`SELECT * from poruke order by vrijeme_slanja;`, async (err, result) => {
            req.poruke = await result.rows;
            next();
        });
    },
    vratiGlavneKategorije: function (req, res, next) {
        pool.query(`SELECT * from kategorija;`, async (err, result) => {
            req.kategorija = await result.rows;
            next();
        });
    },
    vratiKategorijeSaPodkategorijama: function (req, res, next) {
        pool.query(`SELECT * from kategorija k inner join podkategorija p on k.id_kategorije = p.id_kategorije;`, async (err, result) => {
            req.kategorijeSaPodkategorijama = await result.rows;
            next();
        });
    },

    vratiSlikeArtikala: function (req,res,next){
      pool.query(`SELECT * from slikeartikla;`, async (err, result) => {
          req.slikeArt = await result.rows;
          next();
      });
    },
    vratiKomentare: function (req,res,next){
        pool.query(`SELECT * from komentar;`, async (err, result) => {
            req.komentari = await result.rows;
            next();
        });
    },
    vratiBlokirane: function (req,res,next){
        pool.query(`SELECT * from blokirani;`, async (err, result) => {
            req.blokirani = await result.rows;
            next();
        });
    },
  vratiInterese: function (req, res, next) {
    pool.query(`SELECT * from interesi i inner join korisnik k on i.id_korisnika = k.id_korisnika inner join podkategorija p on i.id_podkategorije = p.id_podkategorije;`, async (err, result) => {
      req.interesi = await result.rows;
      next();
    });
  },
  vratiKorisnikeSaSlikama: function (req, res, next) {
    pool.query(`SELECT * from korisnik k inner join slika s on k.id_profilne = s.id_slike left join dodatne_informacije dt on k.id_korisnika = dt.id_trgovca;`, async (err, result) => {
      req.korisniciSlike = await result.rows;
      next();
    });
  },
    vratiNarudzbe: function(req, res, next){
        pool.query(`SELECT * from narudzbe;`, function (err, result){
            req.narudzbe = result.rows;
            next();
        });
    },
    vratiSlike: function (req, res, next) {
        pool.query(`SELECT * from slika;`, async (err, result) => {
            req.slike = await result.rows;
            next();
        });
    },
  vratiNaslovnu: function (req, res, next) {
    pool.query(`SELECT * from slika s inner join korisnik k on s.id_slike = k.id_naslovne;`, async (err, result) => {
      req.vracenaNaslovna = await result.rows;
      next();
    });
  },
  vratiKorisnike: function (req, res, next) {
      pool.query(`SELECT * from korisnik;`, async (err, result) => {
          req.svikorisnici = await result.rows;
          next();
      });
  }};

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var homeRouter = require('./routes/index');
var loginRouter = require('./routes/index');
const {hashSync, compareSync} = require("bcrypt");


var app = express();
app.use(fileUpload());

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
function isNumeric(num){
  return !isNaN(num);
}

//provjera da li je korisnik vec prijavljen, te da li je u medjuvremenu blokiran
app.use(funkcije.vratiKorisnike, function(req, res, next){
  //res.clearCookie('token_prijave');
    if(req.url != '/login' && req.cookies.token_prijave || req.url != '/registracija' && req.cookies.token_prijave){
        var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
        for(let i = 0; i<req.svikorisnici.length; i++){
            if(req.svikorisnici[i].id_korisnika == kuki.id){
                if(req.svikorisnici[i].status == 'Blokiran') res.clearCookie('token_prijave');
                else break;
            }
        }
    }
    if(req.url === '/login' && req.cookies.token_prijave || req.url === '/registracija' && req.cookies.token_prijave){
      return res.redirect('/home');
  }
  if(req.url === '/login' && !req.cookies.token_prijave || req.url === '/registracija' && !req.cookies.token_prijave){
    return next();
  }
  try{
      var decoded = jwt.verify(req.cookies.token_prijave, 'kljuc');
      console.info(decoded);
    next();
  }catch(err){
    res.redirect('/login');
  }

});

//registracija
app.get('/registracija', funkcije.vratiKategorije, function(req, res, next){
  res.render('registracija', { listakategorija: req.podkategorija, title: 'giTare - Registracija' });
});
app.post('/registracija', funkcije.vratiKorisnike, function (req, res, next) {
  if (!req.files.fotka || Object.keys(req.files).length === 0) {
    return res.status(400).send('Niste dodali fotografiju.');
  }
  let fotka = req.files.fotka;
  let putanja;
  if(fotka.size > 5000000){
    return res.status(413).send("Prevelika velicina fajla!");
  }
  const formatfajla = path.extname(fotka.name); // fetch the file extension
  const dozvoljeniformati = ['.png','.jpg','.jpeg'];

  if(!dozvoljeniformati.includes(formatfajla)){
    return res.status(422).send("Nepodrzan format fotografije!");
  }
  var korisnik={
     ime: req.body.ime_unos,
     prezime: req.body.prezime_unos,
     nadimak: req.body.nadimak_unos,
     email: req.body.email_unos,
     sifra: bcrypt.hashSync(req.body.sifra_unos, 10),
     sifrap: req.body.sifrap_unos,
     tip: req.body.selektortipa,
     interes1: req.body.selektor1,
     interes2: req.body.selektor2,
     interes3: req.body.selektor3,
     pfp: req.files.fotka.name,
     brojtelefona: req.body.broj_telefona_unos,
     adresa: req.body.adresa_unos,
  }
  if(korisnik.tip === 'Trgovac') {
    if(!korisnik.brojtelefona || !korisnik.adresa || !isNumeric(korisnik.brojtelefona))return res.status(422).send('Pravilno unesite broj telefona i adresu!');
  }
  if(!bcrypt.compareSync(korisnik.sifrap, korisnik.sifra))return res.status(422).send('Lozinka nepravilno unesena!');
  if(korisnik.sifrap.length<8)return res.status(422).send('Lozinka mora biti barem 8 karaktera duga!')
  if(korisnik.tip === undefined) return res.status(422).send('Odaberite tip vaseg racuna!');
  if(korisnik.tip === 'Kupac') {
    if(korisnik.interes1 === korisnik.interes2 || korisnik.interes1 === korisnik.interes3 || korisnik.interes2 === korisnik.interes3 ||
        korisnik.interes1 === undefined|| korisnik.interes2 === undefined || korisnik.interes3 === undefined) return res.status(422).send('Unesite tri validna interesa!');
  }
  for(let i = 0; i < req.svikorisnici.length; i++){
    if(korisnik.nadimak === req.svikorisnici[i].nadimak) return res.status(409).send('Ovaj nadimak se vec koristi!');
    if(korisnik.email === req.svikorisnici[i].email) return res.status(409).send('Ova email adresa se vec koristi!');
  }
  pool.query(`insert into slika (path_slike, format_slike) values ($1, $2);`, [korisnik.email, path.extname(fotka.name)], function (err, result) {
    pool.query(`select id_slike from slika where path_slike = $1;`, [korisnik.email], function (err, result) {
      req.idfotke = result.rows[0].id_slike;
      putanja = __dirname + '\\public\\images\\profilne\\' + req.idfotke + path.extname(fotka.name);
      fotka.mv(putanja, function(err) {
        if (err)
          return res.status(500).send(err);
      });
          pool.query(`insert into korisnik (ime, prezime, nadimak, email, sifra, tip, id_profilne) values ($1, $2, $3, $4, $5, $6, $7);`,
              [korisnik.ime, korisnik.prezime, korisnik.nadimak, korisnik.email, korisnik.sifra, korisnik.tip, req.idfotke], function (err, result) {
                pool.query(`select id_korisnika from korisnik where email = $1;`, [korisnik.email], function (err, result) {
                  req.idkorisnika = result.rows[0].id_korisnika;
                  if(korisnik.tip ==='Trgovac'){
                    pool.query(`insert into dodatne_informacije(id_trgovca, broj_telefona, adresa) values ($1, $2, $3);`, [req.idkorisnika, korisnik.brojtelefona, korisnik.adresa], async (err, result) => {
                    });
                  }
                  if(korisnik.tip === 'Kupac'){
                      pool.query(`insert into interesi(id_podkategorije, id_korisnika) values ($1, $2), ($3, $4), ($5, $6);`, [korisnik.interes1, req.idkorisnika, korisnik.interes2, req.idkorisnika, korisnik.interes3, req.idkorisnika], async (err, result) => {
                      });
                  }
                });
              });
        });
      });


  return res.redirect('/login');

});

//pocetna stranica
app.get('/home', funkcije.vratiArtikle, funkcije.vratiSlikeArtikala, funkcije.vratiKategorijeSaPodkategorijama, funkcije.vratiGlavneKategorije,  function(req, res, next){
    var decoded = jwt.verify(req.cookies.token_prijave, 'kljuc');
    var artikli = [];
    var slikeArtikala = [];
    if(decoded.tip == 'Kupac'){
        let brojac = 0;
        for(let i = 0; i < req.artikli.length; i++){
            if(req.artikli[i].id_podkategorije == decoded.interes1 || req.artikli[i].id_podkategorije == decoded.interes2 || req.artikli[i].id_podkategorije == decoded.interes3){
                artikli[brojac] = req.artikli[i];
                brojac++;
                if(brojac == 4) break;
            }
        }
        for(let i = 0; i < req.artikli.length; i++){
            artikli[brojac] = req.artikli[i];
            brojac++;
            if(brojac == 8) break;
        }
    }
    if(decoded.tip == 'Trgovac' || decoded.tip == 'Administrator'){
        for(let i = 0; i < 8; i++){
            artikli[i] = req.artikli[i];
        }
    }
    let brojac = 0;
    for(let i = 0; i < artikli.length; i++){
        for(let j = 0; j<req.slikeArt.length; j++){
            if(artikli[i].id_artikla == req.slikeArt[j].id_artikla){
                let rez = req.slikeArt[j].slike;
                let fotke = rez.split(';');
                slikeArtikala[brojac] = fotke[0];
                brojac++;
                break;
            }
        }
    }
    brojac = 0;
    let slikeRandomArtikala = [];
    let randomArtikli = [];
    while(randomArtikli.length != 8){
        let noviArtikal = req.artikli[Math.floor(Math.random() * req.artikli.length)];
        if(!(randomArtikli.includes(noviArtikal))) randomArtikli.push(noviArtikal);
    }
    for(let i = 0; i < randomArtikli.length; i++){
        for(let j = 0; j<req.slikeArt.length; j++){
            if(randomArtikli[i].id_artikla == req.slikeArt[j].id_artikla){
                let rez = req.slikeArt[j].slike;
                let fotke = rez.split(';');
                slikeRandomArtikala[brojac] = fotke[0];
                brojac++;
                break;
            }
        }
    }
    res.render('home', { title: 'giTare - Home', slikeArtikala: slikeArtikala, slikeRandomArtikala: slikeRandomArtikala, randomArtikli: randomArtikli, kuki: decoded, artikli: artikli, podkategorije: req.kategorijeSaPodkategorijama, kategorije: req.kategorija});
});

//login
app.get('/login', function(req, res, next){
  res.render('login', {title: 'giTare - Login' });
});
app.post('/login', funkcije.vratiInterese, funkcije.vratiBlokirane, funkcije.vratiKorisnikeSaSlikama, funkcije.vratiNaslovnu, function(req, res, next){
  let tipKorisnika;
  var pronadjen = false;
  var idKorisnika;
  var nazivProfilne;
  var nadimak;
  var nazivNaslovne = '';
  var status;
  var br_tel = null;
  var adresa = null;
  var ime_korisnika;
  var prezime_korisnika;
  var inter = {};
  var brojac = 0;
  var int1 = null;
  var int2 = null;
  var int3 = null;
    for(let i = 0; i < req.korisniciSlike.length; i++){
        if(req.body.email === req.korisniciSlike[i].email){
            pronadjen = true;
            nadimak = req.korisniciSlike[i].nadimak;
            br_tel = req.korisniciSlike[i].broj_telefona;
            adresa = req.korisniciSlike[i].adresa;
            idKorisnika = req.korisniciSlike[i].id_korisnika;
            status = req.korisniciSlike[i].status;
            if(status == 'Blokiran'){
                for(let i = 0; i<req.blokirani.length; i++){
                    if(req.blokirani[i].id_korisnika == idKorisnika){
                        let datumIsteka = new Date(req.blokirani[i].dan_isteka);
                        let danasnjiDatum = new Date();
                        if(datumIsteka <= danasnjiDatum){
                            pool.query(`update korisnik set status = 'Uredan' where id_korisnika = $1;`,[idKorisnika], async (err, result) => {
                            });
                            pool.query(`delete from blokirani where id_korisnika = $1;`,[idKorisnika], async (err, result) => {
                            });
                        }
                        else{
                            return res.redirect('/login');
                        }
                    }
                }
            }
            tipKorisnika = req.korisniciSlike[i].tip;
            if(tipKorisnika == 'Kupac'){
                for (let i = 0; i < req.interesi.length; i++) {
                    if (req.interesi[i].id_korisnika === idKorisnika) {
                        inter[brojac] = req.interesi[i].id_podkategorije;
                        brojac++;
                    }
                }
                int1 = inter[0];
                int2 = inter[1];
                int3 = inter[2];
            }
            ime_korisnika = req.korisniciSlike[i].ime;
            prezime_korisnika = req.korisniciSlike[i].prezime;
            nazivProfilne = req.korisniciSlike[i].id_profilne + req.korisniciSlike[i].format_slike;
            if(!bcrypt.compareSync(req.body.sifra, req.korisniciSlike[i].sifra))return res.status(422).send('Nepravilno unesena lozinka!');
            pool.query(`select max(id_slike) from slika where path_slike = $1;`, [req.korisniciSlike[i].nadimak], async (err, result) => {
                nazivNaslovne = result.rows[0].max;
                if(nazivNaslovne != null){
                    pool.query(`select format_slike from slika where id_slike = $1;`, [nazivNaslovne], async (err, result) => {
                        nazivNaslovne += await result.rows[0].format_slike;
                        if(!pronadjen)return res.status(404).send('Korisnik ne postoji! Registrujte se ili pokušajte ponovo!');
                        var prijava = {
                            email: req.body.email,
                            status: status,
                            tip: tipKorisnika,
                            id: idKorisnika,
                            naziv_profilne: nazivProfilne,
                            naziv_naslovne: nazivNaslovne,
                            nadimak: nadimak,
                            brtel: br_tel,
                            adresa: adresa,
                            ime: ime_korisnika,
                            prezime: prezime_korisnika,
                            sifra: req.body.sifra,
                            interes1: int1,
                            interes2: int2,
                            interes3: int3
                        }
                        let token = jwt.sign(prijava, 'kljuc');
                        res.cookie("token_prijave", token);
                        res.redirect('/home');
                    });

                }
                else if(nazivNaslovne == null){
                        nazivNaslovne = '0.jpg';
                        if(!pronadjen)return res.status(404).send('Korisnik ne postoji! Registrujte se ili pokušajte ponovo!');
                        var prijava = {
                            email: req.body.email,
                            tip: tipKorisnika,
                            id: idKorisnika,
                            status: status,
                            naziv_profilne: nazivProfilne,
                            naziv_naslovne: nazivNaslovne,
                            nadimak: nadimak,
                            brtel: br_tel,
                            adresa: adresa,
                            ime: ime_korisnika,
                            prezime: prezime_korisnika,
                            sifra: req.body.sifra,
                            interes1: int1,
                            interes2: int2,
                            interes3: int3
                        }
                        let token = jwt.sign(prijava, 'kljuc');
                        res.cookie("token_prijave", token);
                        res.redirect('/home');
                }

            });
        }
    }

});

//ruta koja se poziva pri promjeni korisnickih podataka, da se korisnik ne mora odjavljivati da vidi promjene
app.get('/resetCookies', funkcije.vratiInterese, funkcije.vratiKorisnikeSaSlikama, funkcije.vratiNaslovnu, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    let sifra = kuki.sifra;
    let email = kuki.email;
    let idKorisnika = kuki.id;
    res.clearCookie('token_prijave');
    let inter = {};
    let brojac = 0;
    for (let i = 0; i < req.interesi.length; i++) {
        if (req.interesi[i].id_korisnika === idKorisnika) {
            inter[brojac] = req.interesi[i].id_podkategorije;
            brojac++;
        }
    }
    let int1 = inter[0];
    let int2 = inter[1];
    let int3 = inter[2];
    let tipKorisnika;
    var pronadjen = false;
    var nazivProfilne;
    var nadimak;
    var nazivNaslovne = '';
    var br_tel = null;
    var adresa = null;
    var ime_korisnika;
    var prezime_korisnika;
    for(let i = 0; i < req.korisniciSlike.length; i++){
        if(kuki.email === req.korisniciSlike[i].email){
            pronadjen = true;
            nadimak = req.korisniciSlike[i].nadimak;
            br_tel = req.korisniciSlike[i].broj_telefona;
            adresa = req.korisniciSlike[i].adresa;
            tipKorisnika = req.korisniciSlike[i].tip;
            ime_korisnika = req.korisniciSlike[i].ime;
            prezime_korisnika = req.korisniciSlike[i].prezime;
            pool.query(`select max(id_slike) from slika where path_slike = $1`, [email], function (err, result) {
                nazivProfilne = result.rows[0].max;
                pool.query(`select format_slike from slika where id_slike = $1;`, [nazivProfilne], async (err, result) => {
                    nazivProfilne += result.rows[0].format_slike;
                    pool.query(`select max(id_slike) from slika where path_slike = $1;`, [req.korisniciSlike[i].nadimak], async (err, result) => {
                        nazivNaslovne = result.rows[0].max;
                        if (nazivNaslovne != null) {
                            pool.query(`select format_slike from slika where id_slike = $1;`, [nazivNaslovne], async (err, result) => {
                                nazivNaslovne += await result.rows[0].format_slike;
                                if (!pronadjen) return res.status(404).send('Korisnik ne postoji! Registrujte se ili pokušajte ponovo!');
                                var prijava = {
                                    email: email,
                                    tip: tipKorisnika,
                                    id: idKorisnika,
                                    naziv_profilne: nazivProfilne,
                                    naziv_naslovne: nazivNaslovne,
                                    nadimak: nadimak,
                                    brtel: br_tel,
                                    adresa: adresa,
                                    ime: ime_korisnika,
                                    prezime: prezime_korisnika,
                                    sifra: sifra,
                                    interes1: int1,
                                    interes2: int2,
                                    interes3: int3
                                }
                                let token = jwt.sign(prijava, 'kljuc');
                                res.cookie("token_prijave", token);
                                res.redirect('/home');
                            });

                        } else if (nazivNaslovne == null) {
                            nazivNaslovne = '0.jpg';
                            if (!pronadjen) return res.status(404).send('Korisnik ne postoji! Registrujte se ili pokušajte ponovo!');
                            var prijava = {
                                email: email,
                                tip: tipKorisnika,
                                id: idKorisnika,
                                naziv_profilne: nazivProfilne,
                                naziv_naslovne: nazivNaslovne,
                                nadimak: nadimak,
                                brtel: br_tel,
                                adresa: adresa,
                                ime: ime_korisnika,
                                prezime: prezime_korisnika,
                                sifra: sifra,
                                interes1: int1,
                                interes2: int2,
                                interes3: int3
                            }
                            let token = jwt.sign(prijava, 'kljuc');
                            res.cookie("token_prijave", token);
                            res.redirect('/home');
                        }
                    });
                });
            });
        }
    }
});

//odjava
app.get('/odjava', function(req, res, next){
  res.clearCookie('token_prijave');
  res.redirect('login');
});

//uredjivanje profila
app.get('/urediProfil/:idk', funkcije.vratiInterese, funkcije.vratiKategorije, funkcije.vratiKorisnikeSaSlikama, function(req, res, next){
  var decoded = jwt.verify(req.cookies.token_prijave, 'kljuc');
  if(decoded.status == 'Arhiviran') return res.redirect('/home');
    if (parseInt(req.params.idk) !== parseInt(decoded.id)) return res.redirect('/home');
    else{
    let inter = {};
    let brojac = 0;
    for (let i = 0; i < req.interesi.length; i++) {
      if (req.interesi[i].id_korisnika == decoded.id) {
        inter[brojac] = req.interesi[i];
        brojac++;
      }
    }
    res.render('urediProfil', {
      interesi: inter,
      listakategorija: req.podkategorija,
      title: 'giTare - Uredi profil',
      kuki: decoded,
      podaci: req.korisniciSlike
    });
  }
});
app.post('/urediProfil/:idk', funkcije.vratiInterese, function(req, res, next){
  var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if (req.files) {
        let fotka = req.files.fotka;
        let putanja;
        if(fotka.size > 5000000){
            return res.status(413).send("Prevelika velicina fajla!");
        }
        const formatfajla = path.extname(fotka.name); // fetch the file extension
        const dozvoljeniformati = ['.png','.jpg','.jpeg'];

        if(!dozvoljeniformati.includes(formatfajla)){
            return res.status(422).send("Nepodrzan format fotografije!");
        }
        pool.query(`insert into slika (path_slike, format_slike) values ($1, $2);`, [kuki.email, path.extname(fotka.name)], function (err, result) {
            pool.query(`select max(id_slike) from slika where path_slike = $1;`, [kuki.email], function (err, result) {
                req.idfotke = result.rows[0].max;
                putanja = __dirname + '\\public\\images\\profilne\\' + req.idfotke + path.extname(fotka.name);
                fotka.mv(putanja, function(err) {
                    if (err)
                        return res.status(500).send(err);
                });
                try {
                    fs.unlinkSync(__dirname + '\\public\\images\\profilne\\' + kuki.naziv_profilne)
                    //file removed
                } catch(err) {
                    console.error(err)
                }
                pool.query(`update korisnik set id_profilne = $1 where id_korisnika = $2;`, [req.idfotke, kuki.id], async (err, result) => {
                });
            });
        });
    }

  var podaci = {
    ime: req.body.imeedit,
    prezime: req.body.prezimeedit,
    starasifra: req.body.staraLozinka,
    novasifra: req.body.novaLozinka,
    novasifrap: req.body.novaLozinkaPon,
    telefon: req.body.brteledit,
    adresa: req.body.adresaedit,
    int1: req.body.selektor1,
    int2: req.body.selektor2,
    int3: req.body.selektor3
  }
  if(kuki.tip == 'Kupac' && (podaci.int1 === podaci.int2 || podaci.int1 === podaci.int3 || podaci.int2 === podaci.int3)) return res.status(422).send('Unesite tri validna interesa!');
  let inter = {};
  let brojac = 0;
  for (let i = 0; i < req.interesi.length; i++) {
    if (req.interesi[i].id_korisnika == kuki.id) {
      inter[brojac] = req.interesi[i].id_podkategorije;
      brojac++;
    }
  }
  if(podaci.ime != kuki.ime){
    pool.query(`update korisnik set ime = $1 where id_korisnika = $2;`, [podaci.ime, kuki.id], async (err, result) => {
    });
  }
  if(podaci.prezime != kuki.prezime){
    pool.query(`update korisnik set prezime = $1 where id_korisnika = $2;`, [podaci.prezime, kuki.id], async (err, result) => {
    });
  }
  if(podaci.telefon != null && kuki.tip == 'Trgovac' && podaci.telefon != kuki.brtel){
    pool.query(`update dodatne_informacije set broj_telefona = $1 where id_trgovca = $2;`, [podaci.telefon, kuki.id], async (err, result) => {
    });
  }
  if(podaci.adresa != null && kuki.tip == 'Trgovac' && podaci.adresa != kuki.adresa){
    pool.query(`update dodatne_informacije set adresa = $1 where id_trgovca = $2;`, [podaci.adresa, kuki.id], async (err, result) => {
    });
  }
  if(podaci.starasifra == kuki.sifra && podaci.novasifra == podaci.novasifrap){
    pool.query(`update korisnik set sifra = $1 where id_korisnika = $2;`, [bcrypt.hashSync(podaci.novasifra, 10), kuki.id], async (err, result) => {
    });
  }

  if(podaci.int1 != inter[0] || podaci.int2 != inter[1] || podaci.int3 != inter[2]){
    pool.query(`delete from interesi where id_korisnika = $1;`, [kuki.id], async (err, result) => {
      pool.query(`insert into interesi(id_podkategorije, id_korisnika) values ($1, $2), ($3, $4), ($5, $6);`, [podaci.int1, kuki.id, podaci.int2, kuki.id, podaci.int3, kuki.id], async (err, result) => {
      });
    });

  }

  res.redirect('/resetCookies');
});

//dodavanje artikala
app.get('/dodajArtikal', funkcije.vratiKategorije, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.status == 'Arhiviran') return res.redirect('/home');
    if(kuki.tip == 'Kupac' || kuki.tip == 'Administrator') return res.redirect('/home');
    res.render('dodajArtikal', { listakategorija: req.podkategorija, title: 'giTare - Dodaj artikal' });
});
app.post('/dodajArtikal', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(req.files.fotke.length == undefined) return res.status(413).send('Mora biti vise od jedne fotografije');
    if(req.files.fotke.length > 10 || req.files.fotke.length <= 0) return res.status(413).send('Broj fotografija mora biti izmedju 2 i 10!')
    const dozvoljeniformati = ['.png','.jpg','.jpeg'];
    for(let i = 0; i<req.files.fotke; i++){
        let fotka = req.files.fotke[i];
        if(fotka.size > 5000000){
            return res.status(413).send("Prevelika velicina fajla!");
        }
        const formatfajla = path.extname(fotka.name); // fetch the file extension
        if(!dozvoljeniformati.includes(formatfajla)){
            return res.status(422).send("Nepodrzan format fotografije!");
        }
    }

    var artikal = {
        naziv: req.body.nazivA,
        opis: req.body.opisA,
        id_kategorije: req.body.selektorKategorije,
        id_korisnika: kuki.id,
        kolicina: req.body.kolicinaA,
        cijena: req.body.cijenaA,
        stanje: req.body.selektorStanja
    }
    if(artikal.naziv == '')return res.status(412).send('Naziv artikla ne moze biti prazan!');
    if(artikal.opis == '')return res.status(412).send('Opis artikla ne moze biti prazan!');
    if(artikal.naziv == '')return res.status(412).send('Naziv artikla ne moze biti prazan!');
    if(artikal.cijena == '' || artikal.cijena == 0)return res.status(412).send('Naziv artikla ne moze biti prazan!');
    let nizFotki = '';
    if(artikal.opis.length > 599)return res.status(412).send('Opis artikla mora biti kraci!');

    pool.query(`insert into artikal (naziv_artikla, opis_artikla, id_podkategorije, id_korisnika, kolicina, cijena, stanje) values ($1, $2, $3, $4, $5, $6, $7);`,
        [artikal.naziv, artikal.opis, artikal.id_kategorije, artikal.id_korisnika, artikal.kolicina, artikal.cijena, artikal.stanje], function (err, result) {
        pool.query(`select id_artikla from artikal where naziv_artikla = $1 and opis_artikla = $2 and id_korisnika = $3 and cijena = $4 and stanje = $5;`,
            [artikal.naziv, artikal.opis, artikal.id_korisnika, artikal.cijena, artikal.stanje], function (err, result) {
            let idartikla = result.rows[0].id_artikla;
            for(let i = 0; i<req.files.fotke.length; i++){
                let fotka = req.files.fotke[i];
                let putanja = __dirname + '\\public\\images\\artikli\\' + idartikla + '_' + i + path.extname(fotka.name);
                fotka.mv(putanja, function(err) {
                    if (err) return res.status(500).send(err);
                });
                nizFotki = nizFotki + idartikla + '_' + i + path.extname(fotka.name) + ';';
            }
            pool.query(`insert into slikeartikla (id_artikla, slike) values ($1, $2);`, [idartikla, nizFotki], function (err, result) {

            });
        });
        });

    res.redirect('/home');
});

//uredjivanje artikala
app.get('/urediArtikal/:ida', funkcije.vratiArtikle, funkcije.vratiKategorije, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.status == 'Arhiviran') return res.redirect('/home');
    if(kuki.tip === 'Kupac') return res.redirect('/home');
    let idArtikla = req.params.ida;
    let artikal;
    for(let i = 0; i<req.artikli.length; i++){
        if(req.artikli[i].id_artikla == idArtikla){
            artikal = req.artikli[i];
            break;
        }
    }

    if(kuki.id != artikal.id_korisnika && kuki.tip != 'Administrator') return res.redirect('/home');
    res.render('urediArtikal', { listakategorija: req.podkategorija, artikal: artikal, title: 'giTare - Uredi artikal' });
});
app.post('/urediArtikal/:ida', funkcije.vratiArtikle, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip === 'Kupac') return res.redirect('/home');
    let idArtikla = req.params.ida;
    let artikal;
    for(let i = 0; i<req.artikli.length; i++){
        if(req.artikli[i].id_artikla == idArtikla){
            artikal = req.artikli[i];
            break;
        }
    }
    if(kuki.id != artikal.id_korisnika && kuki.tip != 'Administrator') return res.redirect('/home');
    if(req.body.nazivA == '') return res.status(412).send('Morati unijeti validan naziv artikla!');
    if(req.body.opisA == '') return res.status(412).send('Morati unijeti validan opis artikla!');
    if(req.body.cijenaA == '') return res.status(412).send('Morati unijeti validnu cijenu artikla!');
    if(req.body.nazivA != artikal.naziv_artikla){
        pool.query(`update artikal set naziv_artikla = $1 where id_artikla = $2;`, [req.body.nazivA, idArtikla], async (err, result) => {
        });
    }
    if(req.body.opisA != artikal.opis_artikla){
        pool.query(`update artikal set opis_artikla = $1 where id_artikla = $2;`, [req.body.opisA, idArtikla], async (err, result) => {
        });
    }
    if(req.body.selektorKategorije != artikal.id_podkategorije){
        pool.query(`update artikal set id_podkategorije = $1 where id_artikla = $2;`, [req.body.selektorKategorije, idArtikla], async (err, result) => {
        });
    }
    if(req.body.kolicinaA != artikal.kolicina){
        pool.query(`update artikal set kolicina = $1 where id_artikla = $2;`, [req.body.kolicinaA, idArtikla], async (err, result) => {
        });
    }
    if(req.body.cijenaA != artikal.cijena){
        pool.query(`update artikal set cijena = $1 where id_artikla = $2;`, [req.body.cijenaA, idArtikla], async (err, result) => {
        });
    }
    if(req.body.selektorStanja != artikal.stanje){
        pool.query(`update artikal set stanje = $1 where id_artikla = $2;`, [req.body.selektorStanja, idArtikla], async (err, result) => {
        });
    }
    let ruta = '/artikal/' + idArtikla;
    res.redirect(ruta);
});

//prikaz artikla
app.get('/artikal/:ida', funkcije.vratiKomentare, funkcije.vratiKorisnike, funkcije.vratiKategorijeSaPodkategorijama, funkcije.vratiSlike, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');

    let trazeniId = req.params.ida;
    pool.query(`select * from artikal where id_artikla = $1;`, [trazeniId], async (err, result) => {
        req.art = result.rows;
        pool.query(`select * from slikeartikla where id_artikla = $1;`, [trazeniId], async (err, result) => {

            let slike = await result.rows[0].slike;
            slike = slike.split(';')
            let korisnik;
            for(let i = 0; i<req.svikorisnici.length; i++){
                if(req.art[0].id_korisnika == req.svikorisnici[i].id_korisnika){
                    korisnik = req.svikorisnici[i];
                }
            }
            let profilna;
            let naslovna = '0.jpg';
            for(let i = 0; i<req.slike.length; i++){
                if(korisnik.id_profilne === req.slike[i].id_slike) profilna = req.slike[i].id_slike + req.slike[i].format_slike;
                if(korisnik.id_naslovne === req.slike[i].id_slike) naslovna = req.slike[i].id_slike + req.slike[i].format_slike;
            }
            let podkat;
            for(let i = 0; i<req.kategorijeSaPodkategorijama.length; i++){
                if(req.kategorijeSaPodkategorijama[i].id_podkategorije == req.art[0].id_podkategorije){
                    podkat = req.kategorijeSaPodkategorijama[i].naziv_podkategorije;
                    break;
                }
            }
            let prosjecnaocjena = null;
            let zbir = 0;
            let brojac = 0;
            let brojpregleda = req.art[0].broj_pregleda;
            brojpregleda++;
            let komentari = [];
            let korisniciKomentara = [];
            let ocjene = [];
            for(let i = 0; i<req.komentari.length; i++){
                if(req.komentari[i].id_artikla == req.params.ida){
                    komentari.push(req.komentari[i]);
                    zbir += req.komentari[i].ocjena;
                    ocjene.push(req.komentari[i].ocjena)
                    brojac++;
                }
            }
            if(zbir > 0){
                prosjecnaocjena = zbir / brojac;
            }
            for(let i = 0; i<komentari.length; i++){
                for(let j = 0; j<req.svikorisnici.length; j++){
                    if(req.svikorisnici[j].id_korisnika == komentari[i].id_korisnika){
                        korisniciKomentara.push(req.svikorisnici[j]);
                        break;
                    }
                }
            }
            let datum = new Date(req.art[0].timestamp);
            let formatiraniDatum = datum.getDate() + '.' + (datum.getMonth()+1) + '.' + datum.getFullYear() + '.';
            let formatiranoVrijeme = (datum.getHours()+1) + ':' + datum.getMinutes();
            pool.query(`update artikal set broj_pregleda = $1 where id_artikla = $2;`, [brojpregleda, req.art[0].id_artikla], async (err, result) => {
                res.render('artikal', { brojpregleda: brojpregleda, datum: formatiraniDatum, ocjene: ocjene, brojrecenzija: brojac, prosjecnaocjena: prosjecnaocjena, komentari: komentari, korisniciKomentara: korisniciKomentara, podkategorija: podkat, vrijeme: formatiranoVrijeme, kuki: kuki, pfp: profilna, nas: naslovna, korisnik: korisnik, title: 'giTare - ' + req.art[0].naziv_artikla, artikal: req.art[0], slike: slike});
            });
        });
    });
});

//prikaz profila trenutnog korisnika
app.get('/mojProfil/:idm', funkcije.vratiInterese, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.id === req.params.idm) return res.redirect('/home');
    if(kuki.tip === 'Trgovac'){

    }
    let inter = {};
    let brojac = 0;
    if(kuki.tip === 'Kupac'){
        for(let i = 0; i<req.interesi.length; i++){
            if(req.interesi[i].id_korisnika === kuki.id){
                inter[brojac] = req.interesi[i].naziv_podkategorije;
                brojac++;
            }
        }
    }
    res.render('mojProfil', {kuki:kuki, title: 'giTare - Moj profil', interesi: inter});
});

//prikaz profila drugih korisnika
app.get('/korisnik/:idk', funkcije.vratiArtikle, funkcije.vratiKomentare, funkcije.vratiBlokirane, funkcije.vratiSlikeArtikala, funkcije.vratiKorisnikeSaSlikama, funkcije.vratiNaslovnu, funkcije.vratiInterese, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.id == req.params.idk) return res.redirect('/mojProfil/'+kuki.id);
    let korisnik;
    for(let i = 0; i<req.korisniciSlike.length; i++){
        if(req.params.idk == req.korisniciSlike[i].id_korisnika){
            korisnik = req.korisniciSlike[i];
            if(korisnik.tip == 'Administrator')res.redirect('/home');
            break;
        }
    }
    let satiOdblokiranja;
    let datumOdblokiranja;

    if(korisnik.status == 'Blokiran'){
        for(let i = 0; i<req.blokirani.length; i++){
            if(req.blokirani[i].id_korisnika == korisnik.id_korisnika){
                let datum = new Date(req.blokirani[i].dan_isteka);
                datumOdblokiranja = datum.getDate() + '.' + (datum.getMonth()+1) + '.' + datum.getFullYear() + '.';
                if(datum.getHours()<10){
                    satiOdblokiranja = '0' + (datum.getHours()+1);
                }
                else{
                    satiOdblokiranja = (datum.getHours()+1);
                }
                if(datum.getMinutes()<10){
                    satiOdblokiranja += ':0' + datum.getMinutes();
                }
                else{
                    satiOdblokiranja +=':' + datum.getMinutes();
                }
                break;
            }
        }
    }
    let nazivProfilne = korisnik.id_profilne + korisnik.format_slike;
    let nazivNaslovne;
    for(let i = 0; i<req.vracenaNaslovna.length; i++){
        if(korisnik.id_naslovne == req.vracenaNaslovna[i].id_slike){
            nazivNaslovne = req.vracenaNaslovna[i].id_slike + req.vracenaNaslovna[i].format_slike;
        }
    }

    let inter = {};
    let brojac = 0;
    if(korisnik.tip === 'Kupac'){
        for(let i = 0; i<req.interesi.length; i++){
            if(req.interesi[i].id_korisnika === korisnik.id){
                inter[brojac] = req.interesi[i].naziv_podkategorije;
                brojac++;
            }
        }
    }
    let prosjecnaOcjena = 0;
    let brojacOcjena = 0;
    if(korisnik.tip === 'Trgovac'){
        for(let i = 0; i<req.komentari.length; i++){
            for(let j = 0; j<req.artikli.length; j++){
                if(req.komentari[i].id_artikla == req.artikli[j].id_artikla && req.artikli[j].id_korisnika == korisnik.id_korisnika){
                    prosjecnaOcjena += req.komentari[i].ocjena;
                    brojacOcjena++;
                }
            }
        }
    }
    prosjecnaOcjena = prosjecnaOcjena / brojacOcjena;
    res.render('korisnik', {prosjecnaOcjena: prosjecnaOcjena, title: 'giTare - Korisnik '+ korisnik.nadimak, dan_isteka: datumOdblokiranja, vrijeme_isteka: satiOdblokiranja, kuki: kuki, korisnik: korisnik, nazivNaslovne: nazivNaslovne, nazivProfilne: nazivProfilne, interesi: inter});
});

//ruta koja se poziva kada korisnik mijenja naslovnu sliku
app.post('/mojProfil/:idm', function(req, res, next) {
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    let trenutnanaslovna = kuki.naziv_naslovne;
    let fotka = req.files.novanaslovna;
    let putanja;
    if(fotka.size > 5000000){
        return res.status(413).send("Prevelika velicina fajla!");
    }
    const formatfajla = path.extname(fotka.name); // fetch the file extension
    const dozvoljeniformati = ['.png','.jpg','.jpeg'];

    if(!dozvoljeniformati.includes(formatfajla)){
        return res.status(422).send("Nepodrzan format fotografije!");
    }
    pool.query(`insert into slika (path_slike, format_slike) values ($1, $2);`, [kuki.nadimak, path.extname(fotka.name)], function (err, result) {
        pool.query(`select max(id_slike) from slika where path_slike = $1;`, [kuki.nadimak], function (err, result) {
            req.idfotke = result.rows[0].max;
            putanja = __dirname + '\\public\\images\\naslovne\\' + req.idfotke + path.extname(fotka.name);
            fotka.mv(putanja, function(err) {
                if (err)
                    return res.status(500).send(err);
            });
            if(trenutnanaslovna != '0.jpg') {
                try {
                    fs.unlinkSync(__dirname + '\\public\\images\\naslovne\\' + kuki.naziv_naslovne)
                    //file removed
                } catch (err) {
                    console.error(err)
                }
            }
            pool.query(`update korisnik set id_naslovne = $1 where id_korisnika = $2;`, [req.idfotke, kuki.id], async (err, result) => {
            });
            res.redirect('/resetCookies');
        });
    });
});

//sistem ruta za korpu kupca
app.get('/dodajUKorpu/:ida', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.status == 'Arhiviran') return res.redirect('/home');
    if(kuki.tip === 'Trgovac' || kuki.tip === 'Administrator') return res.redirect('/home');
    let idArtikla = req.params.ida;
    pool.query(`insert into korpa (id_korisnika, id_artikla) values ($1, $2);`, [kuki.id, idArtikla], function (err, result) {
        res.redirect('/home');
    });
});
app.get('/korpa/:idk', funkcije.vratiKorpe, funkcije.vratiArtikle, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.status == 'Arhiviran') return res.redirect('/home');
    if(kuki.tip != 'Kupac')res.redirect('/home');
    let idArtikala = [];
    let sviArtikli = [];
    for(let i = 0; i<req.korpe.length; i++){
        if(req.korpe[i].id_korisnika == kuki.id){
            idArtikala.push(req.korpe[i].id_artikla);
        }
    }
    for(let i = 0; i<idArtikala.length; i++){
        for(let j = 0; j<req.artikli.length; j++){
            if(idArtikala[i] == req.artikli[j].id_artikla){
                sviArtikli.push(req.artikli[j]);
                break;
            }
        }
    }
    let ukupno = 0;
    for(let i = 0; i < sviArtikli.length; i++){
        ukupno+=sviArtikli[i].cijena;
    }
    res.render('korpa', {kuki: kuki, ukupno: ukupno, naziviArtikala: sviArtikli, title: 'giTare - Korpa'});
});
app.get('/ukloniIzKorpe/:ida/:idk', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Kupac') res.redirect('/home');
    if(kuki.id != req.params.idk) res.redirect('/home');
    pool.query(`delete from korpa where id_korisnika = $1 and id_artikla = $2;`, [req.params.idk, req.params.ida], function (err, result) {
        res.redirect('/korpa/'+ kuki.id);
    });
});

//artikli nekog trgovca
app.get('/artikli/:idk', funkcije.vratiArtikle, funkcije.vratiSlikeArtikala, funkcije.vratiKorisnikeSaSlikama, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    let korisnik;
    for(let i = 0; i<req.korisniciSlike.length; i++){
        if(req.params.idk == req.korisniciSlike[i].id_korisnika){
            korisnik = req.korisniciSlike[i];
            break;
        }
    }
    let nazivProfilne = korisnik.id_profilne + korisnik.format_slike;
    let artikli = [];
    let slikeArtikala = [];
    if(korisnik.tip === 'Kupac') res.redirect('/home');

    if(korisnik.tip === 'Trgovac'){
        for(let i = 0; i<req.artikli.length; i++){
            if(req.artikli[i].id_korisnika == korisnik.id_korisnika){
                artikli.push(req.artikli[i]);
            }
        }
        for(let i = 0; i < artikli.length; i++){
            for(let j = 0; j<req.slikeArt.length; j++){
                if(artikli[i].id_artikla == req.slikeArt[j].id_artikla){
                    let rez = req.slikeArt[j].slike;
                    let fotke = rez.split(';');
                    slikeArtikala.push(fotke[0]);
                    break;
                }
            }
        }
    }
    res.render('artikli', {nazivProfilne: nazivProfilne, title: 'giTare - Artikli korisnika '+ korisnik.nadimak, kuki: kuki, korisnik: korisnik, artikli: artikli, slikeArtikala: slikeArtikala})

});

//prikaz artikala po nekoj kategoriji/podkategoriji
app.get('/podkategorije/:idp/:sortiranje/:br', funkcije.vratiKategorijeSaPodkategorijama, funkcije.vratiArtikle, funkcije.vratiSlikeArtikala, funkcije.vratiArtiklePoCijeni, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    let artikli = [];
    let slikeArtikala = [];
    if(req.params.sortiranje == 'vrijemeDesc') {
        for (let i = 0; i < req.artikli.length; i++) {
            if (req.artikli[i].id_podkategorije == req.params.idp) {
                artikli.push(req.artikli[i]);
            }
        }
    }
    if(req.params.sortiranje == 'vrijemeAsc') {
        for (let i = req.artikli.length-1; i > -1; i--) {
            if (req.artikli[i].id_podkategorije == req.params.idp) {
                artikli.push(req.artikli[i]);
            }
        }
    }
    if(req.params.sortiranje == 'cijenaDesc') {
        for (let i = 0; i < req.artikliCijena.length; i++) {
            if (req.artikliCijena[i].id_podkategorije == req.params.idp) {
                artikli.push(req.artikliCijena[i]);
            }
        }
    }
    if(req.params.sortiranje == 'cijenaAsc') {
        for (let i = req.artikliCijena.length-1; i > -1; i--) {
            if (req.artikliCijena[i].id_podkategorije == req.params.idp) {
                artikli.push(req.artikliCijena[i]);
            }
        }
    }
    if(artikli.length == 0) return res.redirect('/home');
    let ukupnoMogucihStranica;
    if(artikli.length % 12 == 0) ukupnoMogucihStranica = artikli.length / 12;
    else{
    ukupnoMogucihStranica = Math.floor(artikli.length / 12) + 1;
    }
    let pocetniIndeks = req.params.br * 12 - 12;
    let krajnjiIndeks = req.params.br * 12;
    let prikazaniArtikli = [];
    for(let i = pocetniIndeks; i<krajnjiIndeks; i++){
        if(i >= artikli.length)break;
        prikazaniArtikli.push(artikli[i]);
    }
    if(prikazaniArtikli.length == 0) res.redirect('/podkategorije/' + req.params.idp + '/' + req.params.sortiranje + '/1');
    artikli = prikazaniArtikli;
    for (let i = 0; i < artikli.length; i++) {
        for (let j = 0; j < req.slikeArt.length; j++) {
            if (artikli[i].id_artikla == req.slikeArt[j].id_artikla) {
                let rez = req.slikeArt[j].slike;
                let fotke = rez.split(';');
                slikeArtikala.push(fotke[0]);
                break;
            }
        }
    }
    let imePodkategorije;
    let nacinSortiranja = null;
    if(req.params.sortiranje == 'vrijemeDesc')nacinSortiranja = 'Najnovijeg';
    if(req.params.sortiranje == 'vrijemeAsc')nacinSortiranja = 'Najstarijeg';
    if(req.params.sortiranje == 'cijenaDesc')nacinSortiranja = 'Najskupljeg';
    if(req.params.sortiranje == 'cijenaAsc')nacinSortiranja = 'Najjeftinijeg';
    if(nacinSortiranja == null)res.redirect('/home');

    for(let i = 0; i<req.kategorijeSaPodkategorijama.length; i++){
        if(req.params.idp == req.kategorijeSaPodkategorijama[i].id_podkategorije){
            imePodkategorije = req.kategorijeSaPodkategorijama[i].naziv_podkategorije;
            break;
        }
    }
    res.render('podkategorija', {title: 'GiTare - Pretraga po kategoriji', idPodkategorije: req.params.idp, sortiranjeParametar: req.params.sortiranje, brojstranice: parseInt(req.params.br), ukupnoMogucihStranica: ukupnoMogucihStranica, sortiranje: nacinSortiranja, imePodkategorije: imePodkategorije, kuki: kuki, artikli: artikli, slikeArtikala: slikeArtikala})
});
app.get('/kategorije/:idp/:sortiranje/:br', funkcije.vratiKategorijeSaPodkategorijama, funkcije.vratiArtikle, funkcije.vratiSlikeArtikala, funkcije.vratiArtiklePoCijeni, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    let artikli = [];
    let slikeArtikala = [];
    let listaKategorija = [];
    for(let i = 0; i<req.kategorijeSaPodkategorijama.length; i++){
        if(req.kategorijeSaPodkategorijama[i].id_kategorije == req.params.idp){
            listaKategorija.push(req.kategorijeSaPodkategorijama[i].id_podkategorije);
        }
    }
    if(req.params.sortiranje == 'vrijemeDesc') {
        for (let i = 0; i < req.artikli.length; i++) {
            for(let j = 0; j < listaKategorija.length; j++){
                if (req.artikli[i].id_podkategorije == listaKategorija[j]){
                    artikli.push(req.artikli[i]);
                }
            }
        }
    }
    if(req.params.sortiranje == 'vrijemeAsc') {
        for (let i = req.artikli.length-1; i > -1; i--) {
            for(let j = 0; j < listaKategorija.length; j++){
                if (req.artikli[i].id_podkategorije == listaKategorija[j]){
                    artikli.push(req.artikli[i]);
                }
            }
        }
    }
    if(req.params.sortiranje == 'cijenaDesc') {
        for (let i = 0; i < req.artikliCijena.length; i++) {
            for(let j = 0; j < listaKategorija.length; j++){
                if (req.artikliCijena[i].id_podkategorije == listaKategorija[j]){
                    artikli.push(req.artikliCijena[i]);
                }
            }
        }
    }
    if(req.params.sortiranje == 'cijenaAsc') {
        for (let i = req.artikliCijena.length-1; i > -1; i--) {
            for(let j = 0; j < listaKategorija.length; j++){
                if (req.artikliCijena[i].id_podkategorije == listaKategorija[j]){
                    artikli.push(req.artikliCijena[i]);
                }
            }
        }
    }
    if(artikli.length == 0) return res.redirect('/home');
    let ukupnoMogucihStranica;
    if(artikli.length % 2 == 0) ukupnoMogucihStranica = artikli.length / 12;
    else{
        ukupnoMogucihStranica = Math.floor(artikli.length / 12) + 1;
    }
    let pocetniIndeks = req.params.br * 12 - 12;
    let krajnjiIndeks = req.params.br * 12;
    let prikazaniArtikli = [];
    for(let i = pocetniIndeks; i<krajnjiIndeks; i++){
        if(i >= artikli.length)break;
        prikazaniArtikli.push(artikli[i]);
    }
    if(prikazaniArtikli.length == 0) res.redirect('/kategorije/' + req.params.idp + '/' + req.params.sortiranje + '/1');
    artikli = prikazaniArtikli;
    for (let i = 0; i < artikli.length; i++) {
        for (let j = 0; j < req.slikeArt.length; j++) {
            if (artikli[i].id_artikla == req.slikeArt[j].id_artikla) {
                let rez = req.slikeArt[j].slike;
                let fotke = rez.split(';');
                slikeArtikala.push(fotke[0]);
                break;
            }
        }
    }
    let imeKategorije;
    let nacinSortiranja = null;
    if(req.params.sortiranje == 'vrijemeDesc')nacinSortiranja = 'Najnovijeg';
    if(req.params.sortiranje == 'vrijemeAsc')nacinSortiranja = 'Najstarijeg';
    if(req.params.sortiranje == 'cijenaDesc')nacinSortiranja = 'Najskupljeg';
    if(req.params.sortiranje == 'cijenaAsc')nacinSortiranja = 'Najjeftinijeg';
    if(nacinSortiranja == null)res.redirect('/home');

    for(let i = 0; i<req.kategorijeSaPodkategorijama.length; i++){
        if(req.params.idp == req.kategorijeSaPodkategorijama[i].id_kategorije){
            imeKategorije = req.kategorijeSaPodkategorijama[i].naziv_kategorije;
            break;
        }
    }
    res.render('kategorija', {title: 'GiTare - Pretraga po kategoriji', idKategorije: req.params.idp, sortiranjeParametar: req.params.sortiranje, brojstranice: parseInt(req.params.br), ukupnoMogucihStranica: ukupnoMogucihStranica, sortiranje: nacinSortiranja, imeKategorije: imeKategorije, kuki: kuki, artikli: artikli, slikeArtikala: slikeArtikala})
});

//brisanje artikla
app.get('/obrisiArtikal/:ida', funkcije.vratiArtikle, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.status == 'Arhiviran') return res.redirect('/home');
    for(let i = 0; i < req.artikli.length; i++){
        if(req.artikli[i].id_artikla == req.params.ida){
            if(req.artikli[i].id_korisnika != kuki.id && kuki.tip != 'Administrator') return res.status(401).send('Nemate dozvolu za ovu operaciju!');
            else{
                pool.query(`delete from komentar where id_artikla = $1;`, [req.params.ida], function (err, result) {
                    pool.query(`delete from korpa where id_artikla = $1;`, [req.params.ida], function (err, result) {
                        pool.query(`delete from slikeartikla where id_artikla = $1;`, [req.params.ida], function (err, result) {
                            glob("**/" + req.params.ida + "_*", function (er, files) {
                                for (const file of files) {
                                    fs.unlinkSync(file);
                                }
                            });
                            pool.query(`delete from artikal where id_artikla = $1;`, [req.params.ida], function (err, result) {
                                res.redirect('/home');
                            });
                        });
                    });
                });
            }
        }
    }
});

//sistem ruta za rukovodjenje korisnicima (blokiranje/arhiviranje) od strane admina
app.get('/blokirajKorisnika/:idk', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Administrator') return res.redirect('/home');
    pool.query(`update korisnik set status = 'Blokiran' where id_korisnika = $1;`, [req.params.idk], function (err, result) {
        pool.query(`insert into blokirani(id_korisnika) values ($1);`, [req.params.idk], function (err, result) {
            res.redirect('/korisnik/' + req.params.idk);
        });

    });
});
app.get('/arhivirajKorisnika/:idk', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Administrator') return res.redirect('/home');
    pool.query(`update korisnik set status = 'Arhiviran' where id_korisnika = $1;`, [req.params.idk], function (err, result) {
        res.redirect('/korisnik/' + req.params.idk);
    });
});
app.get('/odblokirajKorisnika/:idk', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Administrator') return res.redirect('/home');
    pool.query(`update korisnik set status = 'Uredan' where id_korisnika = $1;`, [req.params.idk], function (err, result) {
        pool.query(`delete from blokirani where id_korisnika = $1;`, [req.params.idk], function (err, result) {
            res.redirect('/korisnik/' + req.params.idk);
        });

    });
});
app.get('/odarhivirajKorisnika/:idk', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Administrator') return res.redirect('/home');
    pool.query(`update korisnik set status = 'Uredan' where id_korisnika = $1;`, [req.params.idk], function (err, result) {
        res.redirect('/korisnik/' + req.params.idk);
    });
});

//narudzbe kupaca nakon sto su potvrdjene u korpi
app.get('/stanjaNarudzbi/:idk', funkcije.vratiNarudzbe, funkcije.vratiArtikle, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.status == 'Arhiviran') return res.redirect('/home');
    if(kuki.id != req.params.idk) res.redirect('/home');
    let spisak = [];
    let artikli = [];
    for(let i = 0; i<req.narudzbe.length; i++){
        if(req.narudzbe[i].id_kupca == req.params.idk){
            spisak.push(req.narudzbe[i]);
        }
    }
    for(let i = 0; i<spisak.length; i++){
        for(let j = 0; j < req.artikli.length; j++){
            if(req.artikli[j].id_artikla == spisak[i].id_artikla){
                artikli.push(req.artikli[j]);
            }
        }
    }
    res.render('stanjanarudzbikupac', {title: 'GiTare - Stanje narudzbi', kuki: kuki, spisak: spisak, artikli: artikli})

});
app.get('/ukloniNarudzbu/:ida/:idk', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Kupac') res.redirect('/home');
    if(kuki.id != req.params.idk) res.redirect('/home');
    pool.query(`delete from narudzbe where id_kupca = $1 and id_artikla = $2;`, [req.params.idk, req.params.ida], function (err, result) {
        res.redirect('/stanjaNarudzbi/'+ kuki.id);
    });
});
app.get('/potvrdiNarudzbu/:idk', funkcije.vratiArtikle, function(req, res, next){
    pool.query(`select * from korpa where id_korisnika = $1;`, [req.params.idk], function (err, result) {
        let artikli = result.rows;
        for(let i = 0; i < artikli.length; i++){
            for(let j = 0; j < req.artikli.length; j++){
                if(artikli[i].id_artikla == req.artikli[j].id_artikla) {
                    pool.query(`insert into narudzbe (id_kupca, id_artikla, id_trgovca) values ($1, $2, $3);`, [req.params.idk, parseInt(artikli[i].id_artikla), parseInt(req.artikli[j].id_korisnika)], function (err, result) {
                        pool.query(`delete from korpa where id_artikla = $1 and id_korisnika = $2;`, [parseInt(artikli[i].id_artikla), req.params.idk], function (err, result) {
                        });
                    });
                }
            }
        }
        res.redirect('/stanjaNarudzbi/' + req.params.idk);
    });
});
app.get('/kupiOdmah/:ida/:idk/:idt', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Kupac') return res.redirect('/home');
    pool.query(`insert into narudzbe (id_kupca, id_artikla, id_trgovca) values ($1, $2, $3);`, [req.params.idk, req.params.ida, req.params.idt], function (err, result) {
        res.redirect('/stanjaNarudzbi/' + req.params.idk);
    });
});

//narudzbe koje cekaju potvrdu/odbijanje sa strane trgovca
app.get('/narudzbe/:idk', funkcije.vratiNarudzbe, funkcije.vratiArtikle, funkcije.vratiKorisnike, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.status == 'Arhiviran') return res.redirect('/home');
    if(kuki.id != req.params.idk || kuki.tip == 'Kupac') return res.redirect('/home');
    let spisak = [];
    let artikli = [];
    let korisnici = [];
    for(let i = 0; i<req.narudzbe.length; i++){
        if(req.narudzbe[i].id_trgovca == req.params.idk && req.narudzbe[i].status == 'Na cekanju'){
            spisak.push(req.narudzbe[i]);
        }
    }
    for(let i = 0; i<req.artikli.length; i++){
        for(let j = 0; j < spisak.length; j++){
            if(req.artikli[i].id_artikla == spisak[j].id_artikla){
                artikli.push(req.artikli[i]);
            }
        }
    }
    for(let i = 0; i<spisak.length; i++){
        for(let j = 0; j<req.svikorisnici.length; j++){
            if(spisak[i].id_kupca == req.svikorisnici[j].id_korisnika){
                korisnici.push(req.svikorisnici[j]);
            }
        }
    }
    res.render('narudzbe', {title: 'GiTare - Narudzbe', kuki: kuki, spisak: spisak, artikli: artikli, kupci: korisnici})

});
app.get('/prihvatiNarudzbu/:ida/:idk/:idt', funkcije.vratiKorisnike, funkcije.vratiArtikle, function(req,res,next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.id != req.params.idt) return res.redirect('/home');
    let email;
    let artikal;
    for(let i = 0; i<req.svikorisnici.length; i++){
        if(req.svikorisnici[i].id_korisnika == req.params.idk){
            email = req.svikorisnici[i].email;
            break;
        }
    }
    for(let i = 0; i<req.artikli.length; i++){
        if(req.artikli[i].id_artikla == req.params.ida){
            artikal = req.artikli[i].naziv_artikla;
            break;
        }
    }
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'webshopgitare@gmail.com',
            pass: 'tarikturkovic1'
        }
    });

    var mailOptions = {
        from: 'webshopgitare@gmail.com',
        to: email,
        subject: 'Vasa narudzba je prihvacena.',
        text: 'Vasa narudzba za artikal ' + artikal + ' je prihvacena.'
    };

    transporter.sendMail(mailOptions, function(error, info){
        if (error) {
            console.log(error);
        }
    });
    pool.query(`update narudzbe set status = 'Prihvacen' where id_artikla = $1 and id_kupca = $2 and id_trgovca = $3;`, [req.params.ida, req.params.idk, req.params.idt], function (err, result) {
        return res.redirect('/narudzbe/' + req.params.idt);
    });
});
app.get('/odbijNarudzbu/:ida/:idk/:idt', function(req,res,next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.id != req.params.idt) return res.redirect('/home');
    pool.query(`update narudzbe set status = 'Odbijen' where id_artikla = $1 and id_kupca = $2 and id_trgovca = $3 and status = 'Na cekanju';`, [req.params.ida, req.params.idk, req.params.idt], function (err, result) {
        return res.redirect('/narudzbe/' + req.params.idt);
    });
});

//ruta za pretragu
app.post('/home', function(req, res, next){
   let pretraga = req.body.pretraga;
   if(pretraga == '') return res.redirect('/home');
   let rijeci = pretraga.split(' ');
   for(let i = 0; i<rijeci.length; i++){
       rijeci[i] = rijeci[i].replace(/^\s+|\s+$/g, "");
   }
    const pojedinacne = rijeci.filter(element => {
        return element !== '';
    });
   let ruta = '/pretraga/';
   for(let i = 0; i< pojedinacne.length; i++){
       ruta += pojedinacne[i];
       if(i != pojedinacne.length-1) ruta += '+';
   }
   res.redirect(ruta);
});

//postavljanje recenzije
app.post('/artikal/:ida', function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Kupac')return res.redirect('/home');
    let komentar = req.body.komentarinput;
    if(komentar.length == 0) return res.status(412).send('Komentar prazan!')
    if(komentar.length >= 600) return res.status(412).send('Predug komentar!')
    let ocjena = req.body.ocjena;
    pool.query(`select from komentar where id_artikla = $1 and id_korisnika = $2;`, [req.params.ida, kuki.id], function (err, result) {
        if(result.rows.length != 0){
            pool.query(`delete from komentar where id_artikla = $1 and id_korisnika = $2;`, [req.params.ida, kuki.id], function (err, result) {
                pool.query(`insert into komentar(id_korisnika, id_artikla, sadrzaj, ocjena) values($1, $2, $3, $4);`, [kuki.id, req.params.ida, komentar, ocjena], function (err, result) {
                    res.redirect('/artikal/' + req.params.ida);
                });
            });
        }
        else{
            pool.query(`insert into komentar(id_korisnika, id_artikla, sadrzaj, ocjena) values($1, $2, $3, $4);`, [kuki.id, req.params.ida, komentar, ocjena], function (err, result) {
                res.redirect('/artikal/' + req.params.ida);
            });
        }
    });
});

//brisanje recenzija
app.get('/obrisiKomentar/:ida/:idk', function(req,res,next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(req.params.idk != kuki.id) return res.redirect('/home');
    pool.query(`delete from komentar where id_korisnika = $1 and id_artikla = $2;`, [req.params.idk, req.params.ida], function (err, result) {
        pool.query(`delete from ocjena where id_korisnika = $1 and id_artikla = $2;`, [req.params.idk, req.params.ida], function (err, result) {
            res.redirect('/artikal/' + req.params.ida);
        });
    });
});

//prikaz pretrage
app.get('/pretraga/:rijeci', funkcije.vratiArtikle, funkcije.vratiKorisnikeSaSlikama, funkcije.vratiSlikeArtikala, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    let rijeci = req.params.rijeci.split('+');
    let slikeArtikala = [];
    let artikli = [];
    let korisnici = [];
    for(let i = 0; i<req.artikli.length; i++){
        let pronadjen = false;
        let nazivartikla = req.artikli[i].naziv_artikla;
        let pojedinacne = nazivartikla.split(' ');
        for(let k = 0; k<pojedinacne.length; k++){
            for(let h = 0; h<rijeci.length; h++){
                if(stringSimilarity.compareTwoStrings(pojedinacne[k], rijeci[h])>0.6){
                    artikli.push(req.artikli[i]);
                    pronadjen = true;
                    break;
                }
            }
            if(pronadjen)break;
        }
        if(!pronadjen){
            let opisartikla = req.artikli[i].opis_artikla;
            let pojedinacne = opisartikla.split(' ');
            for(let k = 0; k<pojedinacne.length; k++){
                for(let h = 0; h<rijeci.length; h++){
                    if(stringSimilarity.compareTwoStrings(pojedinacne[k], rijeci[h])>0.6){
                        artikli.push(req.artikli[i]);
                        pronadjen = true;
                        break;
                    }
                }
                if(pronadjen)break;
            }
        }
    }
    for(let i = 0; i<req.korisniciSlike.length; i++){
        let ime = req.korisniciSlike[i].ime;
        let prezime = req.korisniciSlike[i].prezime;
        let nadimak = req.korisniciSlike[i].nadimak;
        for(let j = 0; j<rijeci.length; j++){
            if((stringSimilarity.compareTwoStrings(ime, rijeci[j])>0.6 || stringSimilarity.compareTwoStrings(prezime, rijeci[j])>0.6 || stringSimilarity.compareTwoStrings(nadimak, rijeci[j])>0.6) && req.korisniciSlike[i].tip != 'Administrator'){
                korisnici.push(req.korisniciSlike[i]);
                break;
            }
        }
    }
    for (let i = 0; i < artikli.length; i++) {
        for (let j = 0; j < req.slikeArt.length; j++) {
            if (artikli[i].id_artikla == req.slikeArt[j].id_artikla) {
                let rez = req.slikeArt[j].slike;
                let fotke = rez.split(';');
                slikeArtikala.push(fotke[0]);
                break;
            }
        }
    }
    res.render('pretraga', {title: 'GiTare - Pretraga', kuki: kuki, artikli: artikli, korisnici: korisnici, slikeArtikala: slikeArtikala, rijeci: req.params.rijeci.replace('+', ' ')})
});

//chat sa nekim korisnikom po id-u
app.get('/poruke/:idp',  funkcije.vratiKorisnikeSaSlikama, funkcije.vratiPoruke, function(req,res,next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    let korisnik = null;
    for(let i = 0; i<req.korisniciSlike.length; i++){
        if(req.korisniciSlike[i].id_korisnika == req.params.idp){
            korisnik = req.korisniciSlike[i];
            break;
        }
    }
    if(korisnik == null) return res.redirect('/home');
    let korisnici = new Set();
    let historijaKorisnika = new Set();
    for(let i = 0; i<req.poruke.length; i++){
        if(req.poruke[i].id_posiljaoca == kuki.id){
            historijaKorisnika.add(req.poruke[i].id_primaoca);
        }
        if(req.poruke[i].id_primaoca == kuki.id){
            historijaKorisnika.add(req.poruke[i].id_posiljaoca);
        }
    }
    historijaKorisnika = Array.from(historijaKorisnika);
    for(let i = 0; i<historijaKorisnika.length; i++){
        for(let j = 0; j<req.korisniciSlike.length; j++){
            if(historijaKorisnika[i] == req.korisniciSlike[j].id_korisnika){
                korisnici.add(req.korisniciSlike[j]);
            }
        }
    }
    korisnici = Array.from(korisnici);
    let nazivpfp = korisnik.id_profilne + korisnik.format_slike;
    let historijaPoruka = [];
    for(let i = 0; i<req.poruke.length; i++){
        if((req.poruke[i].id_posiljaoca == kuki.id && req.poruke[i].id_primaoca == req.params.idp) || (req.poruke[i].id_posiljaoca == req.params.idp && req.poruke[i].id_primaoca == kuki.id)){
            historijaPoruka.push(req.poruke[i]);
        }
    }


    io = require('socket.io')(req.connection.server);
    io.on('connection', function(socket){
        console.info('konektovan korisnik ' + kuki.nadimak);

        socket.on('poruke', (poruke, id)=>{
            io.emit('poruke', poruke, id);
            pool.query(`insert into poruke(id_posiljaoca, id_primaoca, poruka) values($1, $2, $3);`, [kuki.id, korisnik.id_korisnika, poruke], function (err, result) {
            });
        })
        socket.on('disconnect', function(){
            console.info('diskonektovan korisnik ' + kuki.nadimak);
        });
    });

    res.render('poruke', {title: 'GiTare - Chat', historijaKorisnika: historijaKorisnika, korisnici: korisnici, historija: historijaPoruka, nazivpfp: nazivpfp, korisnik: korisnik, kuki: kuki})
});

//prikaz chat prozora sa historijom razgovora
app.get('/poruke', funkcije.vratiKorisnikeSaSlikama, funkcije.vratiPoruke, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    let korisnici = new Set();
    let historijaKorisnika = new Set();
    for(let i = 0; i<req.poruke.length; i++){
        if(req.poruke[i].id_posiljaoca == kuki.id){
            historijaKorisnika.add(req.poruke[i].id_primaoca);
        }
        if(req.poruke[i].id_primaoca == kuki.id){
            historijaKorisnika.add(req.poruke[i].id_posiljaoca);
        }
    }
    historijaKorisnika = Array.from(historijaKorisnika);
    for(let i = 0; i<historijaKorisnika.length; i++){
        for(let j = 0; j<req.korisniciSlike.length; j++){
            if(historijaKorisnika[i] == req.korisniciSlike[j].id_korisnika){
                korisnici.add(req.korisniciSlike[j]);
            }
        }
    }
    korisnici = Array.from(korisnici);
    res.render('porukePrazne', {title: 'GiTare - Chat', historijaKorisnika: historijaKorisnika, korisnici: korisnici, kuki: kuki})

});

//statistika za administratora
app.get('/statistika', funkcije.vratiArtikle, funkcije.vratiKategorijeSaPodkategorijama, funkcije.vratiKorisnike, funkcije.vratiNarudzbe, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Administrator') return res.redirect('/home');
    let brojkorisnika = req.svikorisnici.length;
    let brojkupaca = 0;
    let brojtrgovaca = 0;
    let brojartikala = req.artikli.length;
    let brojnarudzbi = req.narudzbe.length;
    let brojnarudzbinacekanju = 0;
    let brojnarudzbiprihvacenih = 0;
    let brojnarudzbiodbijenih = 0;
    for(let i = 0; i<req.svikorisnici.length; i++){
        if(req.svikorisnici[i].tip == 'Kupac')brojkupaca++;
        if(req.svikorisnici[i].tip == 'Trgovac')brojtrgovaca++;
    }
    let brojadministratora = req.svikorisnici.length - (brojkupaca+brojtrgovaca);

    for(let i = 0; i<req.narudzbe.length; i++){
        if(req.narudzbe[i].status == 'Prihvacen')brojnarudzbiprihvacenih++;
        if(req.narudzbe[i].status == 'Na cekanju')brojnarudzbinacekanju++;
        if(req.narudzbe[i].status == 'Odbijen')brojnarudzbiodbijenih++;

    }
    res.render('statistika', {title: 'GiTare - Statistika', podkategorije: req.kategorijeSaPodkategorijama, artikli: req.artikli, kuki: kuki, brojadministratora:brojadministratora, brojkorisnika: brojkorisnika, brojkupaca:brojkupaca, brojtrgovaca:brojtrgovaca, brojartikala:brojartikala, brojnarudzbi:brojnarudzbi, brojnarudzbiodbijenih: brojnarudzbiodbijenih, brojnarudzbinacekanju:brojnarudzbinacekanju, brojnarudzbiprihvacenih:brojnarudzbiprihvacenih})

});

//dodavanje podkategorije
app.get('/dodajPodkategoriju', funkcije.vratiGlavneKategorije, function(req, res, next){
    var kuki = jwt.verify(req.cookies.token_prijave, 'kljuc');
    if(kuki.tip != 'Administrator') return res.redirect('/home');
    res.render('dodajPodkategoriju', {title: 'Dodaj podkategoriju', kuki: kuki, listakategorija: req.kategorija})
});
app.post('/dodajPodkategoriju', function(req, res, next){
    var kategorija = req.body.selektorKategorije;
    var naziv = req.body.nazivP;
    pool.query(`insert into podkategorija(naziv_podkategorije, id_kategorije) values($1, $2);`, [naziv, kategorija], function (err, result) {
        res.redirect('/home');
    });
});

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/home', homeRouter);
app.use('/login', loginRouter);


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
