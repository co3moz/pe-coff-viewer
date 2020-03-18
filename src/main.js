const s16 = ':sub16';
const contentDOM = document.querySelector('.content');
const fileNameDOM = document.querySelector('.file-name');
const alertDOM = document.querySelector('.alert-danger');
const tipsDOM = document.querySelectorAll('.tip');

let offset = 0;
let _file = null;
let _last_hover = null;
let _file_cache = null;
let _file_sector = null;

['drag', 'dragstart', 'dragend', 'dragover', 'dragenter', 'dragleave', 'drop'].forEach(event => document.body.addEventListener(event, e => { e.preventDefault(); e.stopPropagation(); }));
['dragover', 'dragenter'].forEach(event => document.body.addEventListener(event, e => { document.body.className = 'dropping'; }));
['dragleave', 'dragend', 'drop'].forEach(event => document.body.addEventListener(event, e => { document.body.className = ''; }));

document.body.addEventListener('drop', e => {
  let files = e.dataTransfer.files; if (files.length > 0) parseExe(files[0]);
});

function read(start, end) {
  return new Promise((resolve, reject) => {
    var reader = new FileReader();
    reader.onload = () => resolve(new DataView(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(typeof start != "undefined" ? _file.slice(start, end) : _file);
  })
}

async function parseExe(file) {
  _file = file;
  _file_cache = null;
  _file_sector = 0;
  offset = 0;

  console.time(file.name);

  try {
    fileNameDOM.innerHTML = file.name;
    tipsDOM.forEach(x => x.style.display = 'block');

    if (await byte() != 77 || await byte() != 90) {
      throw new Error('MZ Signature missing.');
    }

    let co = (v) => offsetTxtGen(offset + (v | 0));

    let html = '';
    let e_lfanew = 0;

    html = `<br><hr><h3>@ DOS</h3>`;

    html += list([
      '@lastsize/' + co(), await short(),
      '@nblocks/' + co(), await short(),
      '@nreloc/' + co(), await short(),
      '@hdrsize/' + co(), await short(),
      '@minalloc/' + co(), await short(),
      '@maxalloc/' + co(), await short(),
    ]);

    html += list([
      '@ss/Stack Segment Register' + co(), await short(),
      '@sp/Stack Pointer Register' + co(), await short(),
      '@checksum/' + co(), await short(),
      '@ip/Instruction Pointer' + co(), await short(),
      '@cs/Extend of Instruction Pointer' + co(), await short(),
      '@relocpos/' + co(), await short(),
      '@noverlay/' + co(), await short(),
    ]);

    html += list([
      '@reserved/' + co(),
      ...await repeat(4, async x => await short() + co(- 2))
    ]);

    html += list([
      '@oem_id/' + co(), await short(),
      '@oem_info/' + co(), await short()
    ]);

    html += list([
      '@reserved2/' + co(),
      ...await repeat(10, async x => await short() + co(- 2))
    ]);

    html += list([
      '@e_lfanew/New exe header location' + co(),
      (e_lfanew = await int(), toHex(e_lfanew, 8).replace(/^0+/, '') + s16)
    ]);

    html += '<h4> - code</h4>';
    html += await bin_walk(offset, e_lfanew);

    offset = e_lfanew;

    if (await ushort() == 17744 && await ushort() == 0) {
      html += `<br><hr><h3>@ COFF</h3>`;

      html += list([
        '@machine/Type of machine' + co(), determineMachine(await ushort()),
      ]);

      let nsections;
      html += list([
        '@nsections/' + co(), nsections = await short(),
        '@timestamp/Build date' + co(), basicDate(await int()),
        '@ptrsymbol/' + co(), await int(),
      ]);

      let chr;
      let szoptheader;
      html += list([
        '@nsymbols/' + co(), await int(),
        '@szoptheader/Size of optional header' + co(), szoptheader = await ushort(),
        '@chr/Characteristics' + co(), toHex(chr = await ushort()) + s16,
      ]);

      Object.keys(chrs).forEach(n => {
        if (!(n & chr)) return;
        html += list([
          '@[COFF_CHR] &nbsp;' + chrs[n][0] + '/' + chrs[n][1]
        ], 'chr');
      });

      if (szoptheader) {
        let signature = await short();
        let varying = signature == 523 ? long_hex : int_hex;
        let sigText = signature == 523 ? 'HDR64_MAGIC' : signature == 267 ? 'HDR32_MAGIC' : signature == 263 ? 'HDR_MAGIC' : ('Unknown (' + signature + ')');

        html += list([
          '@signature/' + co(-2), sigText,
          '@verlinker/Linker version' + co(), await ubyte() + '.' + await ubyte(),
          '@szcode/Size Of Code' + co(), await int(),
        ]);

        html += list([
          '@szinitdata/Size Of Initialized Data' + co(), await int(),
          '@szuinitdata/Size Of Uninitialized Data' + co(), await int(),
          '@entrypoint/Address of Entry Point' + co(), await int_hex(),
        ]);

        html += list([
          '@basecode/Base of Code' + co(), await int_hex(),
          '@basedata/Base of Data' + co(), signature == 523 ? 'N/A' : await int_hex(),
          '@imgbase/Image Base' + co(), signature == 523 ? await long_hex() : await int_hex(),
        ]);

        html += list([
          '@secalign/Section alignment' + co(), await int(),
          '@filealign/File alignment' + co(), await int(),
          '@osver/OS Version' + co(), await short() + '.' + await short(),
        ]);

        html += list([
          '@imgver/Image Version' + co(), await short() + '.' + await short(),
          '@subsysver/Subsystem Version' + co(), await short() + '.' + await short(),
          '@reserved/Reserved. (its 0 all the time)' + co(), await int(),
        ]);

        html += list([
          '@szimage/Image Size' + co(), await int(),
          '@szhdr/Header Size' + co(), await int(),
          '@checksum/' + co(), await int(),
        ]);

        let subsystem;
        let dllCharacteristic;

        html += list([
          '@subsystem/Subsystem value' + co(), subsystem = await ushort(),
          '@dllchr/DLL Characteristics' + co(), toHex(dllCharacteristic = await ushort()) + s16,
          '@szstkrsv/Size of Stack Reserve' + co(), await varying(),
        ]);

        if (subsystems[subsystem]) {
          html += list([
            '@' + subsystems[subsystem][0] + '/' + subsystems[subsystem][1]
          ], 'subs');
        } else {
          html += list([
            '@[SUBSYS_CHR] &nbsp; NOT KNOWN / Undefined subsystem!'
          ], 'subs');
        }

        Object.keys(dllCharacteristics).forEach(n => {
          if (!(n & dllCharacteristic)) return;
          html += list([
            '@[DLL_CHR] &nbsp;' + dllCharacteristics[n][0] + '/' + dllCharacteristics[n][1]
          ], 'dll_chr');
        });

        html += list([
          '@szstkcmt/Size of Stack Commit' + co(), await varying(),
          '@szhprsv/Size of Heap Reserve' + co(), await varying(),
          '@szhpcmt/Size of Heap Commit' + co(), await varying(),
        ]);

        await int(); // loader flags..

        html += list([
          '@ddi/Data Directory Index' + co(), '@vaddr/Virtual Address', '@size/Size'
        ]);

        let dd = await int();

        if (dd != 16) throw new Error('probably invalid data directory count! read: ' + dd);

        for (let i = 0; i < dd; i++) {
          let addr = await int();
          let size = await int();

          let id = imageDirectory[i];
          html += list([
            '@' + (id ? (id[0] + ' (' + i + ')' + '/' + id[1]) : i) + ' ' + co(-8),
            (addr ? (toHex(addr) + s16) : 0),
            (size ? (toHex(size) + s16) : 0),
          ], 'nas');
        }


        html += `<h4>- sections</h4>`;
        let utfDecoder = new TextDecoder('utf-8');

        for (let n = 0; n < nsections; n++) {
          let name = await repeat(8, async () => await ubyte());
          let vsize = await int();
          let vaddr = await int();
          let szrawdata = await int();
          let ptrrawdata = await int();
          let ptrreloc = await int();
          let ptrln = await int();
          let nreloc = await short();
          let nln = await short();
          let chr = await uint();

          let name_utf = utfDecoder.decode(new Uint8Array(name)).trim();

          html += list([
            '@section/Section name' + co(-40), name_utf, name.map(x => toHex(x, 2)).join(' '),
          ], 'hsection');

          html += list([
            '@vsize/Virtual size' + co(-32), vsize,
            '@vaddr/Virtual address' + co(-28), toHex(vaddr) + s16,
            '@szrawdata/Size of Raw Data' + co(-24), szrawdata,
          ]);

          html += list([
            '@ptrrawdata/Pointer of Raw Data' + co(-20), ptrrawdata,
            '@ptrreloc/Pointer of Relocations' + co(-16), ptrreloc,
            '@ptrline/Pointer of Line numbers' + co(-12), ptrln
          ]);

          html += list([
            '@nreloc/Number of Relocations' + co(-8), nreloc,
            '@nline/Number of Line numbers' + co(-6), nln,
            '@chr/Section Characteristic value' + co(-4), toHex(chr) + s16
          ]);

          Object.keys(sectionChrs).forEach(n => {
            if (!(n & chr)) return;
            html += list([
              '@[SECTION_CHR] &nbsp;' + sectionChrs[n][0] + '/' + sectionChrs[n][1]
            ], 'sec_chr');
          });

          if (n + 1 != nsections) html += '<div class="section_divider"></div>';

        }
      }
    }


    // html += await bin_dyn(offset, offset + 4096);

    console.log('generated html size: ' + html.length);
    console.log('stop offset: ' + offset);

    html += '<br>'.repeat(10);
    contentDOM.innerHTML = html;

    updateError();
  } catch (e) {
    updateError(e);
    console.log(e ? e.stack || e : e);

    contentDOM.innerHTML = '';
  }

  console.timeEnd(file.name);
}

document.body.onmousemove = function (e) {
  let t = e.target;
  let i = t.getAttribute('i');

  if (i == null) {
    if (_last_hover) {
      _last_hover.classList.remove('hover');
      _last_hover = null;
    }
  } else {
    let h = t.closest('table').getAttribute('h');
    let td = t.closest(h > 2 ? '.bin-dyn' : '.bin-walk').querySelector((h > 2 ? '.bin-dyn' : '.bin-walk') + '-' + ((h == 2 || h == 4) ? 'left' : 'right') + ' tr:nth-child(' + ((i >> 4) + 2) + ') td:nth-child(' + ((i % 16) + (+h & 1)) + ')');

    if (td && (!_last_hover || td != _last_hover)) {
      td.classList.add('hover');
      if (_last_hover) _last_hover.classList.remove('hover');
    }

    _last_hover = td;
  }
}

contentDOM.onclick = function (e) {
  let target = e.target;
  if (!e.ctrlKey || !target || !target.parentNode.classList.contains('list')) return;

  let html = target.innerHTML;
  let sub = html.endsWith('</sub>');

  if (/^-?\d+$/.test(html) || sub) {
    if (sub) {
      let idx = html.lastIndexOf('<sub>');
      sub = html.substring(idx + 5, html.lastIndexOf('</sub>'));

      target.innerHTML = parseInt(html.substring(0, idx), sub);
    } else {
      target.innerHTML = toHex(parseInt(html)) + '<sub>16</sub>';
    }
  }
}

function updateError(err) {
  alertDOM.style.display = err ? 'block' : 'none';
  alertDOM.innerHTML = err ? err.message : '';
}

function basicDate(timestamp) {
  let date = new Date(timestamp * 1000);

  return [date.getDate(), date.getMonth() + 1].map(x => x.toString().padStart(2, '0')).join('.') + '.' + date.getFullYear() + ' ' + [date.getHours(), date.getMinutes(), date.getSeconds()].map(x => x.toString().padStart(2, '0')).join(':');
}


async function prepare() {
  if (!_file_cache) {
    _file_sector = 0;
    _file_cache = await read(_file_sector, _file_sector + 4096 + 8);
  } else {
    let cur_sector = offset & (~4095);

    if (_file_sector != cur_sector) {
      _file_sector = cur_sector;
      _file_cache = await read(_file_sector, _file_sector + 4096 + 8);
    }
  }

  return _file_cache;
}

async function byte() {
  return (await prepare()).getInt8((offset += 1) - 1 - _file_sector);
}

async function ubyte() {
  return (await prepare()).getUint8((offset += 1) - 1 - _file_sector);
}

async function short() {
  return (await prepare()).getInt16((offset += 2) - 2 - _file_sector, true);
}

async function ushort() {
  return (await prepare()).getUint16((offset += 2) - 2 - _file_sector, true);
}

async function int() {
  return (await prepare()).getInt32((offset += 4) - 4 - _file_sector, true);
}

async function uint() {
  return (await prepare()).getUint32((offset += 4) - 4 - _file_sector, true);
}

async function long_hex() {
  let low = await uint();
  let high = await uint();

  return (toHex(high, 8) + toHex(low, 8)).replace(/^0+/, '') + s16;
}

async function int_hex() {
  return toHex(await uint(), 8).replace(/^0+/, '') + s16;
}

function list(array, opt) {
  return ('<div class="row list">' + array.map(x => {
    let regex = /^(@)?([^\/\n#]+)\/?((?<=\/)[^#\n]+)?#?((?<=#)[^\n]+)?/;

    let obj = regex.exec(x + '');

    let isHeader = obj && !!obj[1];
    let txt = ((obj && obj[2]) || '').trim();
    let alt = ((obj && obj[3]) || '').trim();
    let offset = ((obj && obj[4]) || '').trim();

    txt = txt.replace(':sub16', '<sub>16</sub>')

    if (!isHeader && alt) {
      txt += '/' + alt;
      alt = '';
    }

    if (offset) offset = ' offset="' + offset + '" ';
    if (alt) alt = ' alt="' + alt + '" ';

    let classNames = 'class="col' + (isHeader ? ' header' + (opt ? (' ' + opt + '-header') : '') : '') + (opt ? ' ' + opt : '') + '"';
    return '<div ' + classNames + alt + offset + '>' + txt + '</div>'
  }).join('\n') + '</div>');
}

async function repeat(amount, fn) {
  let arr = [];
  for (let i = 0; i < amount; i++) arr.push(await fn());
  return arr;
}

function fromCode(char) {
  if (char < 51) return '.';
  return String.fromCharCode(char);
}

async function bin_walk(s, e) {
  let rs = Math.floor(s / 16) * 16;
  let re = Math.ceil(e / 16) * 16;

  let hexMap = '<tr><td></td>';
  let contentMap = '<tr>';

  for (let i = 0; i < 16; i++) {
    let row = '<td>' + toHex(i) + '</td>';
    hexMap += row;
    contentMap += row;
  }

  hexMap += '</tr>';
  contentMap += '</tr>';

  offset = rs;
  for (let i = rs; i < re; i++) {
    let mod = i % 16;
    if (mod == 0) {
      hexMap += '<tr><td>' + toHex(i) + '</td>';
      contentMap += '<tr>';
    }

    let out = i < s || i >= e ? ' class="out"' : '';
    let alt = toHex(i) + 'h';
    let v = await ubyte();

    hexMap += '<td i="' + (i - rs) + '"' + out + ' alt="' + alt + '">' + toHex(v, 2) + '</td>';
    contentMap += '<td i="' + (i - rs) + '"' + out + ' alt="' + alt + '">' + fromCode(v) + '</td>';
    if (mod == 15) {
      hexMap += '</tr>';
      contentMap += '</tr>';
    }
  }

  return '<div class="row bin-walk">' +
    '<div class="col-md-8 bin-walk-left"><table h="1">' + hexMap + '</table></div>' +
    '<div class="col-md-4 bin-walk-right"><table h="2">' + contentMap + '</table></div>' +
    '</div>';
}

async function bin_dyn(start, end) {
  let real_start = Math.floor(start / 16) * 16;
  let real_end = Math.ceil(end / 16) * 16;

  let hexTable = '';
  let binTable = '';

  offset = real_start;
  let rowHeight = 0;
  for (let i = real_start; i < real_end; i++) {
    let mod = i % 16;
    if (mod == 0) {
      hexTable += '<tr><td>' + toHex(i, 10) + '</td>';
      binTable += '<tr>';
    }

    let out = i < start || i >= end ? ' class="out"' : '';
    let alt = toHex(i) + 'h';
    let v = await ubyte();

    hexTable += '<td i="' + (i - real_start) + '"' + out + ' alt="' + alt + '">' + toHex(v, 2) + '</td>';
    binTable += '<td i="' + (i - real_start) + '"' + out + ' alt="' + alt + '">' + fromCode(v) + '</td>';
    if (mod == 15) {
      hexTable += '</tr>';
      binTable += '</tr>';
      rowHeight++;

      if (rowHeight > 20) break;
    }
  }

  return '<div class="row bin-dyn">' +
    '<div class="col-md-8 bin-dyn-left"><table h="3">' + hexTable + '</table></div>' +
    '<div class="col-md-4 bin-dyn-right"><table h="4">' + binTable + '</table></div>' +
    '</div>';
}

function offsetTxtGen(v) {
  return '#' + toHex(v | 0) + 'h';
}

function toHex(i, p) {
  if (p != undefined) {
    return i.toString(16).toUpperCase().padStart(p, '0');
  }

  return i.toString(16).toUpperCase();
}

function LoadDemo() {
  fetch('basic.exe')
    .then(x => x.blob())
    .then(x => parseExe(new File([x], 'basic.exe')))
    .catch(err => alert('Error occurred! ' + err.message));
}

document.querySelector('.demo').onclick = LoadDemo;

if (location.hash == '#demo') {
  LoadDemo();
}