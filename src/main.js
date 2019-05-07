['drag', 'dragstart', 'dragend', 'dragover', 'dragenter', 'dragleave', 'drop'].forEach(event => {
  document.body.addEventListener(event, function (e) {
    e.preventDefault();
    e.stopPropagation();
  });
});

['dragover', 'dragenter'].forEach(event => {
  document.body.addEventListener(event, e => {
    document.body.className = 'dropping'
  });
});

['dragleave', 'dragend', 'drop'].forEach(event => {
  document.body.addEventListener(event, e => {
    document.body.className = ''
  });
});

document.body.addEventListener('drop', function (e) {
  let files = e.dataTransfer.files;

  for (let i = 0; i < files.length; i++) {
    let file = files[i];

    readAsByte(file, function (data) {
      loadExe(file.name, data);
    });

    break;
  }
});

function readAsByte(file, callback) {
  var reader = new FileReader();
  reader.onload = function () {
    let data = new DataView(reader.result);

    callback(data);
  };
  reader.readAsArrayBuffer(file);
}

const s16 = ':sub16';
const contentDOM = document.querySelector('.content');
const fileNameDOM = document.querySelector('.file-name');
const alertDOM = document.querySelector('.alert-danger');

const offsetTxtGen = (v) => '#' + (v | 0).toString(16).toUpperCase() + 'h';

function loadExe(fileName, data) {
  console.time(fileName);
  try {
    fileNameDOM.innerHTML = fileName;
    document.querySelectorAll('.tip').forEach(x => x.style.display = 'block');

    let f = DataFloater(data);

    if (f.byte() != 77 || f.byte() != 90) {
      throw new Error('MZ Signature missing.');
    }

    let co = (v) => offsetTxtGen(f.offset + (v | 0));

    let html = '';
    let e_lfanew = 0;

    html = `<br><hr><h3>@ DOS</h3>`;

    html += f.list([
      '@lastsize/' + co(), f.short(),
      '@nblocks/' + co(), f.short(),
      '@nreloc/' + co(), f.short(),
      '@hdrsize/' + co(), f.short(),
      '@minalloc/' + co(), f.short(),
      '@maxalloc/' + co(), f.short(),
    ]);

    html += f.list([
      '@ss/Stack Segment Register' + co(), f.short(),
      '@sp/Stack Pointer Register' + co(), f.short(),
      '@checksum/' + co(), f.short(),
      '@ip/Instruction Pointer' + co(), f.short(),
      '@cs/Extend of Instruction Pointer' + co(), f.short(),
      '@relocpos/' + co(), f.short(),
      '@noverlay/' + co(), f.short(),
    ]);

    html += f.list([
      '@reserved/' + co(),
      ...f.repeat(4, x => f.short() + co(- 2))
    ]);

    html += f.list([
      '@oem_id/' + co(), f.short(),
      '@oem_info/' + co(), f.short()
    ]);

    html += f.list([
      '@reserved2/' + co(),
      ...f.repeat(10, x => f.short() + co(- 2))
    ]);

    html += f.list([
      '@e_lfanew/New exe header location' + co(),
      (e_lfanew = f.int(), e_lfanew.toString(16).toUpperCase().padStart(8, '0').replace(/^0+/, '') + s16)
    ]);

    html += '<h4> - code</h4>';
    html += f.bin_walk(f.offset, e_lfanew);

    f.offset = e_lfanew;

    if (f.ushort() == 17744 && f.ushort() == 0) {
      html += `<br><hr><h3>@ COFF</h3>`;

      html += f.list([
        '@machine/Type of machine' + co(), determineMachine(f.ushort()),
      ]);

      let nsections;
      html += f.list([
        '@nsections/' + co(), nsections = f.short(),
        '@timestamp/Build date' + co(), basicDate(f.int()),
        '@ptrsymbol/' + co(), f.int(),
      ]);

      let chr;
      let szoptheader;
      html += f.list([
        '@nsymbols/' + co(), f.int(),
        '@szoptheader/Size of optional header' + co(), szoptheader = f.ushort(),
        '@chr/Characteristics' + co(), (chr = f.ushort()).toString(16) + s16,
      ]);

      Object.keys(chrs).forEach(n => {
        if (!(n & chr)) return;
        html += f.list([
          '@[COFF_CHR] &nbsp;' + chrs[n][0] + '/' + chrs[n][1] + ' (0x' + (+n).toString(16).toUpperCase() + ')'
        ], 'chr');
      });

      if (szoptheader) {
        let signature = f.short();
        let varying = signature == 523 ? f.long_hex : f.int_hex;
        let sigText = signature == 523 ? 'HDR64_MAGIC' : signature == 267 ? 'HDR32_MAGIC' : signature == 263 ? 'HDR_MAGIC' : ('Unknown (' + signature + ')');

        html += f.list([
          '@signature/' + co(-2), sigText,
          '@verlinker/Linker version' + co(), f.ubyte() + '.' + f.ubyte(),
          '@szcode/Size Of Code' + co(), f.int(),
        ]);

        html += f.list([
          '@szinitdata/Size Of Initialized Data' + co(), f.int(),
          '@szuinitdata/Size Of Uninitialized Data' + co(), f.int(),
          '@entrypoint/Address of Entry Point' + co(), f.int_hex(),
        ]);

        html += f.list([
          '@basecode/Base of Code' + co(), f.int_hex(),
          '@basedata/Base of Data' + co(), signature == 523 ? 'N/A' : f.int_hex(),
          '@imgbase/Image Base' + co(), signature == 523 ? f.long_hex() : f.int_hex(),
        ]);

        html += f.list([
          '@secalign/Section alignment' + co(), f.int(),
          '@filealign/File alignment' + co(), f.int(),
          '@osver/OS Version' + co(), f.short() + '.' + f.short(),
        ]);

        html += f.list([
          '@imgver/Image Version' + co(), f.short() + '.' + f.short(),
          '@subsysver/Subsystem Version' + co(), f.short() + '.' + f.short(),
          '@reserved/Reserved. (its 0 all the time)' + co(), f.int(),
        ]);

        html += f.list([
          '@szimage/Image Size' + co(), f.int(),
          '@szhdr/Header Size' + co(), f.int(),
          '@checksum/' + co(), f.int(),
        ]);

        let subsystem;
        let dllCharacteristic;

        html += f.list([
          '@subsystem/Subsystem value' + co(), subsystem = f.ushort(),
          '@dllchr/DLL Characteristics' + co(), (dllCharacteristic = f.ushort()).toString(16) + s16,
          '@szstkrsv/Size of Stack Reserve' + co(), varying(),
        ]);

        if (subsystems[subsystem]) {
          html += f.list([
            '@' + subsystems[subsystem][0] + '/' + subsystems[subsystem][1]
          ], 'subs');
        } else {
          html += f.list([
            '@[SUBSYS_CHR] &nbsp; NOT KNOWN / Undefined subsystem!'
          ], 'subs');
        }

        Object.keys(dllCharacteristics).forEach(n => {
          if (!(n & dllCharacteristic)) return;
          html += f.list([
            '@[DLL_CHR] &nbsp;' + dllCharacteristics[n][0] + '/' + dllCharacteristics[n][1]
          ], 'dll_chr');
        });

        html += f.list([
          '@szstkcmt/Size of Stack Commit' + co(), varying(),
          '@szhprsv/Size of Heap Reserve' + co(), varying(),
          '@szhpcmt/Size of Heap Commit' + co(), varying(),
        ]);

        f.int(); // loader flags..

        html += f.list([
          '@ddi/Data Directory Index' + co(), '@vaddr/Virtual Address', '@size/Size'
        ]);

        let dd = f.int();

        if (dd != 16) throw new Error('probably invalid data directory count! read: ' + dd);

        for (let i = 0; i < dd; i++) {
          let addr = f.int();
          let size = f.int();

          let id = imageDirectory[i];
          html += f.list([
            '@' + (id ? (id[0] + ' (' + i + ')' + '/' + id[1]) : i) + ' ' + co(-8),
            (addr ? (addr.toString(16).toUpperCase() + s16) : 0),
            (size ? (size.toString(16).toUpperCase() + s16) : 0),
          ], 'nas');
        }


        html += `<h4>- sections</h4>`;
        let utfDecoder = new TextDecoder('utf-8');

        for (let n = 0; n < nsections; n++) {
          let name = Array(8).fill(0).map(x => f.ubyte());
          let vsize = f.int();
          let vaddr = f.int();
          let szrawdata = f.int();
          let ptrrawdata = f.int();
          let ptrreloc = f.int();
          let ptrln = f.int();
          let nreloc = f.short();
          let nln = f.short();
          let chr = f.uint();

          let name_utf = utfDecoder.decode(new Uint8Array(name)).trim();

          html += f.list([
            '@section/Section name' + co(-40), name_utf, name.map(x => x.toString(16).toUpperCase().padStart(2, '0')).join(' '),
          ], 'hsection');

          html += f.list([
            '@vsize/Virtual size' + co(-32), vsize,
            '@vaddr/Virtual address' + co(-28), vaddr.toString(16) + s16,
            '@szrawdata/Size of Raw Data' + co(-24), szrawdata,
          ]);

          html += f.list([
            '@ptrrawdata/Pointer of Raw Data' + co(-20), ptrrawdata,
            '@ptrreloc/Pointer of Relocations' + co(-16), ptrreloc,
            '@ptrline/Pointer of Line numbers' + co(-12), ptrln
          ]);

          html += f.list([
            '@nreloc/Number of Relocations' + co(-8), nreloc,
            '@nline/Number of Line numbers' + co(-6), nln,
            '@chr/Section Characteristic value' + co(-4), chr.toString(16).toUpperCase() + s16
          ]);

          Object.keys(sectionChrs).forEach(n => {
            if (!(n & chr)) return;
            html += f.list([
              '@[SECTION_CHR] &nbsp;' + sectionChrs[n][0] + '/' + sectionChrs[n][1]
            ], 'sec_chr');
          });

          if (n + 1 != nsections) html += '<div class="section_divider"></div>';

        }
      }
    }


    console.log('generated html size: ' + html.length);
    console.log('stop offset: ' + f.offset);

    html += '<br>'.repeat(10);
    contentDOM.innerHTML = html;

    updateError();
  } catch (e) {
    updateError(e);
    console.log(e ? e.stack || e : e);

    contentDOM.innerHTML = '';
  }

  console.timeEnd(fileName);
}

let last;
document.body.onmousemove = function (e) {
  let t = e.target;
  let i = t.getAttribute('i');

  if (i == null) {
    if (last) {
      last.classList.remove('hover');
      last = null;
    }
  } else {
    let h = t.closest('table').getAttribute('h');
    let td = t.closest('.bin-walk').querySelector('.bin-walk-' + (h == 2 ? 'left' : 'right') + ' tr:nth-child(' + ((i >> 4) + 2) + ') td:nth-child(' + ((i % 16) + +h) + ')');

    if (td && (!last || td != last)) {
      td.classList.add('hover');
      if (last) last.classList.remove('hover');
    }

    last = td;
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
      target.innerHTML = parseInt(html).toString(16).toUpperCase() + '<sub>16</sub>';
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


function DataFloater(data) {
  let offset = 0;
  let byte = () => data.getInt8((offset += 1) - 1);
  let ubyte = () => data.getUint8((offset += 1) - 1);
  let short = () => data.getInt16((offset += 2) - 2, true);
  let ushort = () => data.getUint16((offset += 2) - 2, true);
  let int = () => data.getInt32((offset += 4) - 4, true);
  let uint = () => data.getUint32((offset += 4) - 4, true);
  let long_hex = () => {
    let low = int();
    let high = int();

    let txt = high.toString(16).toUpperCase().padStart(8, '0') + low.toString(16).toUpperCase().padStart(8, '0');

    return txt.replace(/^0+/, '') + s16;
  };
  let int_hex = () => {
    return uint().toString(16).toUpperCase().padStart(8, '0').replace(/^0+/, '') + s16
  };
  let list = (array, opt) => {
    return ('<div class="row list">' + array.map(x => {
      let regex = /^(@)?([^\/\n#]+)\/?((?<=\/)[^#\n]+)?#?((?<=#)[^\n]+)?/;

      let obj = regex.exec(x + '');

      let isHeader = !!obj[1];
      let txt = (obj[2] || '').trim();
      let alt = (obj[3] || '').trim();
      let offset = (obj[4] || '').trim();

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
  };
  let repeat = (amount, fn) => Array(amount).fill(0).map(fn)
  let fromCode = (char) => {
    if (char < 51) return '.';
    return String.fromCharCode(char);
  }

  let bin_walk = (s, e) => {
    let rs = Math.floor(s / 16) * 16;
    let re = Math.ceil(e / 16) * 16;

    let hexMap = '<tr><td></td>';
    let contentMap = '<tr>';

    for (let i = 0; i < 16; i++) {
      hexMap += '<td>' + i.toString(16).toUpperCase() + '</td>';
      contentMap += '<td>' + i.toString(16).toUpperCase() + '</td>';
    }

    hexMap += '</tr>';
    contentMap += '</tr>';

    for (let i = rs; i < re; i++) {
      let mod = i % 16;
      if (mod == 0) {
        hexMap += '<tr><td>' + (i).toString(16).toUpperCase() + '</td>';
        contentMap += '<tr>';
      }

      let out = i < s || i >= e ? ' class="out"' : '';
      let alt = i.toString(16).toUpperCase() + 'h';
      let v = data.getUint8(i);

      hexMap += '<td i="' + (i - rs) + '"' + out + ' alt="' + alt + '">' + v.toString(16).toUpperCase().padStart(2, '0') + '</td>';
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

  return {
    byte, ubyte, short, ushort, int, uint, long_hex, int_hex, list, repeat, bin_walk, repeat,

    get offset() {
      return offset
    },

    set offset(_o) {
      offset = _o;
    }
  }
}

let loaddemo = () => {
  fetch('basic.exe')
    .then(x => x.arrayBuffer())
    .then(x => loadExe('basic.exe', new DataView(x)))
    .catch(err => alert('Error occurred! ' + err.message));
}

document.querySelector('.demo').onclick = loaddemo;

if (location.hash == '#demo') {
  loaddemo();
}