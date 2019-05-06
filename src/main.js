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

const sub16 = '<sub>16</sub>';
const sub2 = '<sub>2</sub>';
const contentDOM = document.querySelector('.content');
const fileNameDOM = document.querySelector('.file-name');

const offset_string_fn = (v) => 'offset: 0x' + (v | 0).toString(16).toUpperCase();

function loadExe(fileName, data) {
  try {
    fileNameDOM.innerHTML = fileName;
    document.querySelectorAll('.tip').forEach(x => x.style.display = 'block');

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

      return txt.replace(/^0+/, '') + sub16;
    };
    let int_hex = () => {
      return uint().toString(16).toUpperCase().padStart(8, '0').replace(/^0+/, '') + sub16
    }
    let list = (array, className) => {
      return `<div class="row">
        ${array.map(x => {
        let s = x[0] == '@';
        let alt = '';
        let txt = x;

        if (s) {
          let l = x.indexOf('/');
          if (l != -1) {
            alt = x.substring(l + 1);
            txt = x.substring(1, l);
          } else {
            txt = x.substring(1);
          }
        }
        return `<div class="col p-2 list-col ${s ? 'list-header' + (className ? ' ' + className + '-header' : '') : ''} ${className || ''}" ${alt ? ' title="' + alt + '"' : ''}>${txt}</div>`
      }).join('\n')}
      </div>`;
    }
    let repeat = (amount, fn) => Array(amount).fill(0).map(fn)
    let fromCode = (char) => {
      if (char < 51) return '.';
      return String.fromCharCode(char);
    }

    let bin_walk = (s, e) => {
      let rs = Math.floor(s / 16) * 16;
      let re = Math.ceil(e / 16) * 16;

      let bin = data.buffer.slice(rs, re);
      let d = new Uint8Array(bin);

      let hexMap = '<tr><td></td>';
      let contentMap = '<tr>';

      for (let i = 0; i < 16; i++) {
        hexMap += '<td>' + i.toString(16).toUpperCase() + '</td>';
        contentMap += '<td>' + i.toString(16).toUpperCase() + '</td>';
      }

      hexMap += '</tr>';
      contentMap += '</tr>';

      for (let i = 0; i < d.length; i++) {
        let mod = i % 16;
        if (mod == 0) {
          hexMap += '<tr><td>' + (i + rs).toString(16).toUpperCase() + '</td>';
          contentMap += '<tr>';
        }
        let out = (i + rs) < s || (i + rs) >= e;

        let title = offset_string_fn(i + rs);
        hexMap += '<td i="' + i + '" h="1" class="out-' + out + '" title="' + title + '">' + d[i].toString(16).toUpperCase().padStart(2, '0') + '</td>';
        contentMap += '<td i="' + i + '" h="2" class="out-' + out + '" title="' + title + '">' + fromCode(d[i]) + '</td>';
        if (mod == 15) {
          hexMap += '</tr>';
          contentMap += '</tr>';
        }
      }

      return `<div class="row bin-walk">
        <div class="col-md-8 bin-walk-left">
          <table>${hexMap}</table>
        </div> 
        <div class="col-md-4 bin-walk-right">
          <table>${contentMap}</table>
        </div> 
      </div>`
    }

    if (byte() != 77 || byte() != 90) {
      throw new Error('MZ Signature missing.');
    }

    let po = (v) => offset_string_fn(offset + (v | 0));

    let html = '';
    let e_lfanew = 0;


    html = `<h3>@ DOS</h3>`;
    html += list([
      '@lastsize/' + po(), short(),
      '@nblocks/' + po(), short(),
      '@nreloc/' + po(), short(),
      '@hdrsize/' + po(), short(),
      '@minalloc/' + po(), short(),
      '@maxalloc/' + po(), short(),
    ]);
    html += list([
      '@ss/Stack Segment Register | ' + po(), short(),
      '@sp/Stack Pointer Register | ' + po(), short(),
      '@checksum/' + po(), short(),
      '@ip/Instruction Pointer | ' + po(), short(),
      '@cs/Extend of Instruction Pointer | ' + po(), short(),
      '@relocpos/' + po(), short(),
      '@noverlay/' + po(), short(),
    ]);
    html += list([
      '@reserved/' + po(),
      ...repeat(4, x => short())
    ]);
    html += list([
      '@oem_id/' + po(), short(),
      '@oem_info/' + po(), short()
    ]);
    html += list([
      '@reserved2/' + po(),
      ...repeat(10, x => short())
    ]);
    html += list([
      '@e_lfanew/New exe header location | ' + po(),
      e_lfanew = int()
    ]);

    html += '<h4> - code</h4>';
    html += bin_walk(offset, e_lfanew);

    offset = e_lfanew;

    if (ushort() == 17744 && ushort() == 0) {
      html += `<h3>@ COFF</h3>`;
      html += list([
        '@machine/Type of machine' + po(), determineMachine(ushort()),
      ]);
      let nsections;
      html += list([
        '@nsections/' + po(), nsections = short(),
        '@timestamp/Build date | ' + po(), basicDate(int()),
        '@ptrsymbol/' + po(), int(),
      ]);

      let chr;
      let szoptheader;
      html += list([
        '@nsymbols/' + po(), int(),
        '@szoptheader/Size of optional header | ' + po(), szoptheader = ushort(),
        '@chr/Characteristics | ' + po(), (chr = ushort()).toString(2) + sub2,
      ]);

      Object.keys(characteristics).forEach(n => {
        if (!(n & chr)) return;
        html += list([
          '@[COFF_CHR] &nbsp;' + characteristics[n][0] + '/' + characteristics[n][1] + ' (0x' + (+n).toString(16).toUpperCase() + ')'
        ], 'chr');
      });

      if (szoptheader) {
        let signature = short();
        let varying = signature == 523 ? long_hex : int_hex;
        let sigText = signature == 523 ? 'HDR64_MAGIC' : signature == 267 ? 'HDR32_MAGIC' : signature == 263 ? 'HDR_MAGIC' : ('Unknown (' + signature + ')');

        html += list([
          '@signature/' + po(-2), sigText,
          '@verlinker/Linker version | ' + po(), ubyte() + '.' + ubyte(),
          '@szcode/Size Of Code | ' + po(), int(),
        ]);

        html += list([
          '@szinitdata/Size Of Initialized Data | ' + po(), int(),
          '@szuinitdata/Size Of Uninitialized Data | ' + po(), int(),
          '@adrentry/Address of Entry Point | ' + po(), int_hex(),
        ]);
        html += list([
          '@basecode/Base of Code | ' + po(), int_hex(),
          '@basedata/Base of Data | ' + po(), signature == 523 ? 'N/A' : int_hex(),
          '@imgbase/Image Base | ' + po(), signature == 523 ? long_hex() : int_hex(),
        ]);
        html += list([
          '@secalign/Section alignment | ' + po(), int(),
          '@filealign/File alignment | ' + po(), int(),
          '@osver/OS Version | ' + po(), short() + '.' + short(),
        ]);
        html += list([
          '@imgver/Image Version | ' + po(), short() + '.' + short(),
          '@subsysver/Subsystem Version | ' + po(), short() + '.' + short(),
          '@reserved/Reserved. (its 0 all the time) | ' + po(), int(),
        ]);
        html += list([
          '@szimage/Image Size | ' + po(), int(),
          '@szhdr/Header Size | ' + po(), int(),
          '@checksum/' + po(), int(),
        ]);
        let subsystem;
        let dllCharacteristic;

        html += list([
          '@subsystem/Subsystem value | ' + po(), subsystem = ushort(),
          '@dllchr/DLL Characteristics | ' + po(), (dllCharacteristic = ushort(), dllCharacteristic.toString(2)) + sub2,
          '@szstkrsv/Size of Stack Reserve | ' + po(), varying(),
        ]);

        if (subsystems[subsystem]) {
          html += list([
            '@' + subsystems[subsystem][0] + '/' + subsystems[subsystem][1] + '(0x' + subsystem.toString(16).toUpperCase() + ')'
          ], 'subs');
        } else {
          html += list([
            '@[SUBSYS_CHR] &nbsp; NOT KNOWN / Undefined subsystem!'
          ], 'subs');
        }

        Object.keys(dllCharacteristics).forEach(n => {
          if (!(n & dllCharacteristic)) return;
          html += list([
            '@[DLL_CHR] &nbsp;' + dllCharacteristics[n][0] + '/' + dllCharacteristics[n][1] + ' (0x' + (+n).toString(16).toUpperCase() + ')'
          ], 'dll_chr');
        });

        html += list([
          '@szstkcmt/Size of Stack Commit | ' + po(), varying(),
          '@szhprsv/Size of Heap Reserve | ' + po(), varying(),
          '@szhpcmt/Size of Heap Commit | ' + po(), varying(),
        ]);

        int(); // loader flags..

        html += list([
          '@ddi/Data Directory Index | ' + po(), '@addr/Address', '@size/Size'
        ]);

        let dd = int();

        if (dd != 16) throw new Error('probably invalid data directory count! read: ' + dd);

        for (let i = 0; i < dd; i++) {
          let addr = int();
          let size = int();

          let id = imageDirectory[i];
          html += list([
            '@' + (id ? (id[0] + ' (' + i + ')' + '/' + id[1]) : i) + ' ' + po(-8),
            (addr ? (addr.toString(16).toUpperCase() + sub16) : 0),
            (size ? (size.toString(16).toUpperCase() + sub16) : 0),
          ], 'nas');
        }


        html += `<h4>- sections</h4>`;
        let utfDecoder = new TextDecoder('utf-8');

        for (let n = 0; n < nsections; n++) {

          let name = Array(8).fill(0).map(x => ubyte());
          let vsize = int();
          let vaddr = int();
          let szrawdata = int();
          let ptrrawdata = int();
          let ptrreloc = int();
          let ptrln = int();
          let nreloc = short();
          let nln = short();
          let chr = uint();

          let name_utf = utfDecoder.decode(new Uint8Array(name)).trim();
          html += list([
            '@section/Section name ' + po(-40), name_utf, name.map(x => x.toString(16).toUpperCase().padStart(2, '0')).join(' '),
          ], 'hsection');

          html += list([
            '@vsize/Virtual size ' + po(-32), vsize,
            '@vaddr/Virtual address ' + po(-28), vaddr.toString(16) + sub16,
            '@szrawdata/Size of Raw Data ' + po(-24), szrawdata,
          ]);

          html += list([
            '@ptrrawdata/Pointer of Raw Data ' + po(-20), ptrrawdata,
            '@ptrreloc/Pointer of Relocations ' + po(-16), ptrreloc,
            '@ptrline/Pointer of Line numbers ' + po(-12), ptrln
          ]);

          html += list([
            '@nreloc/Number of Relocations ' + po(-8), nreloc,
            '@nline/Number of Line numbers ' + po(-6), nln,
            '@chr/Section Characteristic value ' + po(-4), chr.toString(16).toUpperCase() + sub16
          ]);

          Object.keys(sectionCharacteristics).forEach(n => {
            if (!(n & chr)) return;
            html += list([
              '@[SECTION_CHR] &nbsp;' + sectionCharacteristics[n][0] + '/' + sectionCharacteristics[n][1] + ' (0x' + (+n).toString(16).toUpperCase() + ')'
            ], 'sec_chr');
          });
          html += '<br>';
        }

        console.log(html.length);
        //html += bin_walk(offset, offset + 1024);

        console.log(offset)
      }



    }

    html += '<br>'.repeat(10);

    contentDOM.innerHTML = html;

    updateError();
  } catch (e) {
    updateError(e);

    html = '';
    contentDOM.innerHTML = html;
  }
}

let last;
document.body.onmousemove = function (e) {
  let t = e.target;
  let i = t.getAttribute('i');
  let h = t.getAttribute('h');

  if (!h) {
    if (last) {
      last.classList.remove('hover');
      last = null;
    }
  } else {
    let td = t.closest('.bin-walk').querySelector('.bin-walk-' + (h == 2 ? 'left' : 'right') + ' tr:nth-child(' + ((i >> 4) + 2) + ') td:nth-child(' + ((i % 16) + +h) + ')');

    if (td && (!last || td != last)) {
      td.classList.add('hover')
      if (last) {
        last.classList.remove('hover')
      }
    }

    last = td;
  }
}

contentDOM.onclick = function (e) {
  if (!e.ctrlKey) return;
  let target = e.target;

  if (target) {
    if (target.classList.contains('list-col')) {
      let html = target.innerHTML;
      let sub = html.endsWith('</sub>');
      if (/^-?\d+$/.test(html) || sub) {
        if (sub) {
          let lx = html.lastIndexOf('<sub>');
          let lv = html.substring(0, lx);
          let subValue = html.substring(lx + 5, html.lastIndexOf('</sub>'));

          if (subValue == 16) {
            lv = parseInt(lv, 16);
            target.innerHTML = lv;
          } else if (subValue == 2) {

          }
        } else {
          target.innerHTML = parseInt(html).toString(16).toUpperCase() + sub16;
        }
      }
    }
  }
}

function updateError(err) {
  let alert = document.querySelector('.alert-danger');
  if (err) {
    alert.innerHTML = err.message;
    alert.style.display = 'block';
  } else {
    alert.innerHTML = '';
    alert.style.display = 'none';
  }
}

function basicDate(timestamp) {
  let date = new Date(timestamp * 1000);

  return date.getFullYear() + '/' + (date.getMonth() + 1).toString().padStart(2, '0') + '/' + date.getDate().toString().padStart(2, '0') + ' ' + date.getHours().toString().padStart(2, '0') + ':' + date.getMinutes().toString().padStart(2, '0') + ':' + date.getSeconds().toString().padStart(2, '0')
}


const machines = {
  0x14c: 'Intel 386',
  0x8664: 'x64',
  0x162: 'MIPS R3000',
  0x168: 'MIPS R10000',
  0x169: 'MIPS little endian WCI v2',
  0x183: 'old Alpha AXP',
  0x184: 'Alpha AXP',
  0x1a2: 'Hitachi SH3',
  0x1a3: 'Hitachi SH3 DSP',
  0x1a6: 'Hitachi SH4',
  0x1a8: 'Hitachi SH5',
  0x1c0: 'ARM little endian',
  0x1c2: 'Thumb',
  0x1c4: 'ARMv7',
  0x1d3: 'Matsushita AM33',
  0x1f0: 'PowerPC little endian',
  0x1f1: 'PowerPC with floating point support',
  0x200: 'Intel IA64',
  0x266: 'MIPS16',
  0x268: 'Motorola 68000 series',
  0x284: 'Alpha AXP 64-bit',
  0x366: 'MIPS with FPU',
  0x466: 'MIPS16 with FPU',
  0xebc: 'EFI Byte Code',
  0x9041: 'Mitsubishi M32R little endian',
  0xaa64: 'ARM64 little endian',
  0xc0ee: 'clr pure MSIL'
};

function determineMachine(code) {
  if (machines[code]) return machines[code] + ' (' + code.toString(16).toUpperCase() + sub16 + ')';
  return 'unknown code (' + code + ')';
}

const characteristics = {
  0x0001: ['RELOCS_STRIPPED', 'Relocation information was stripped from file'],
  0x0002: ['EXECUTABLE_IMAGE', 'The file is executable'],
  0x0004: ['LINE_NUMS_STRIPPED', 'COFF line numbers were stripped from file'],
  0x0008: ['LOCAL_SYMS_STRIPPED', 'COFF symbol table entries were stripped from file'],
  0x0010: ['AGGRESIVE_WS_TRIM', 'Aggressively trim the working set(obsolete)'],
  0x0020: ['LARGE_ADDRESS_AWARE', 'The application can handle addresses greater than 2 GB'],
  0x0080: ['BYTES_REVERSED_LO', 'The bytes of the word are reversed(obsolete)'],
  0x0100: ['32BIT_MACHINE', 'The computer supports 32-bit words'],
  0x0200: ['DEBUG_STRIPPED', 'Debugging information was removed and stored separately in another file'],
  0x0400: ['REMOVABLE_RUN_FROM_SWAP', 'If the image is on removable media, copy it to and run it from the swap file'],
  0x0800: ['NET_RUN_FROM_SWAP', 'If the image is on the network, copy it to and run it from the swap file'],
  0x1000: ['SYSTEM', 'The image is a system file'],
  0x2000: ['DLL', 'The image is a DLL file'],
  0x4000: ['UP_SYSTEM_ONLY', 'The image should only be ran on a single processor computer'],
  0x8000: ['BYTES_REVERSED_HI', 'The bytes of the word are reversed(obsolete)']
};

const subsystems = {
  0: ['UNKNOWN', 'Unknown subsystem.'],
  1: ['NATIVE', 'No subsystem required (device drivers and native system processes).'],
  2: ['WINDOWS_GUI', 'Windows graphical user interface (GUI) subsystem.'],
  3: ['WINDOWS_CUI', 'Windows character-mode user interface (CUI) subsystem.'],
  5: ['OS2_CUI', 'OS/2 CUI subsystem.'],
  7: ['POSIX_CUI', 'POSIX CUI subsystem.'],
  9: ['WINDOWS_CE_GUI', 'Windows CE system.'],
  10: ['EFI_APPLICATION', 'Extensible Firmware Interface (EFI) application.'],
  11: ['EFI_BOOT_SERVICE_DRIVER', 'EFI driver with boot services.'],
  12: ['EFI_RUNTIME_DRIVER', 'EFI driver with run-time services.'],
  13: ['EFI_ROM', 'EFI ROM image.'],
  14: ['XBOX', 'Xbox system.'],
  16: ['WINDOWS_BOOT_APPLICATION', 'Boot application.']
};

const dllCharacteristics = {
  0x0001: ['Reserved.', 'Reserved'],
  0x0002: ['Reserved.', 'Reserved'],
  0x0004: ['Reserved.', 'Reserved'],
  0x0008: ['Reserved.', 'Reserved'],
  0x0020: ['HIGH_ENTROPY_VA', 'Image can handle a high entropy 64-bit virtual address space.'],
  0x0040: ['DYNAMIC_BASE', 'The DLL can be relocated at load time.'],
  0x0080: ['FORCE_INTEGRITY', 'Code integrity checks are forced. If you set this flag and a section contains only uninitialized data, set the PointerToRawData member of IMAGE_SECTION_HEADER for that section to zero; otherwise, the image will fail to load because the digital signature cannot be verified.'],
  0x0100: ['NX_COMPAT', 'The image is compatible with data execution prevention (DEP).'],
  0x0200: ['NO_ISOLATION', 'The image is isolation aware, but should not be isolated.'],
  0x0400: ['NO_SEH', 'The image does not use structured exception handling (SEH). No handlers can be called in this image.'],
  0x0800: ['NO_BIND', 'Do not bind the image.'],
  0x1000: ['APPCONTAINER', 'Image must execute in an AppContainer'],
  0x2000: ['WDM_DRIVER', 'A WDM driver.'],
  0x4000: ['GUARD_CF', 'Image supports Control Flow Guard'],
  0x8000: ['TERMINAL_SERVER_AWARE', 'The image is terminal server aware.'],
};

const imageDirectory = {
  0: ['EXPORT', 'Export Directory'],
  1: ['IMPORT', 'Import Directory'],
  2: ['RESOURCE', 'Resource Directory'],
  3: ['EXCEPTION', 'Exception Directory'],
  4: ['SECURITY', 'Security Directory'],
  5: ['BASERELOC', 'Base Relocation Directory'],
  6: ['DEBUG', 'Debug Directory'],
  7: ['ARCHITECTURE', 'Architecture specific data'],
  8: ['GLOBALPTR', 'Global pointer register relative virtual address'],
  9: ['TLS', 'Thread local storage directory'],
  10: ['LOAD_CONFIG', 'Load configuration directory'],
  11: ['BOUND_IMPORT', 'Bound import directory'],
  12: ['IAT', 'Import Address Table'],
  13: ['DELAY_IMPORT', 'Delay Import Table'],
  14: ['COM_DESC', 'COM descriptor table'],
  15: ['RESERVED', 'Reserved'],
};

const sectionCharacteristics = {
  0x0001: ['Reserved', 'Reserved'],
  0x0002: ['Reserved', 'Reserved'],
  0x0004: ['Reserved', 'Reserved'],
  0x0008: ['TYPE_NO_PAD', 'The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES'],
  0x0010: ['Reserved', 'Reserved'],
  0x0020: ['CNT_CODE', 'The section contains executable code'],
  0x0040: ['CNT_INITIALIZED_DATA', 'The section contains initialized data'],
  0x0080: ['CNT_UNINITIALIZED_DATA', 'The section contains uninitialized data'],
  0x0100: ['LNK_OTHER', 'Reserved'],
  0x0200: ['LNK_INFO', 'The section contains comments or other information. This is valid only for object files'],
  0x0400: ['Reserved', 'Reserved'],
  0x0800: ['LNK_REMOVE', 'The section will not become part of the image. This is valid only for object files'],
  0x1000: ['LNK_COMDAT', 'The section contains COMDAT data. This is valid only for object files'],
  0x2000: ['Reserved', 'Reserved'],
  0x4000: ['NO_DEFER_SPEC_EXC', 'Reset speculative exceptions handling bits in the TLB entries for this section'],
  0x8000: ['GPREL', 'The section contains data referenced through the global pointer'],
  0x10000: ['Reserved', 'Reserved'],
  0x20000: ['MEM_PURGEABLE', 'Reserved'],
  0x40000: ['MEM_LOCKED', 'Reserved'],
  0x80000: ['MEM_PRELOAD', 'Reserved'],
  0x100000: ['ALIGN_1BYTES', 'Align data on a 1-byte boundary. This is valid only for object files'],
  0x200000: ['ALIGN_2BYTES', 'Align data on a 2-byte boundary. This is valid only for object files'],
  0x300000: ['ALIGN_4BYTES', 'Align data on a 4-byte boundary. This is valid only for object files'],
  0x400000: ['ALIGN_8BYTES', 'Align data on a 8-byte boundary. This is valid only for object files'],
  0x500000: ['ALIGN_16BYTES', 'Align data on a 16-byte boundary. This is valid only for object files'],
  0x600000: ['ALIGN_32BYTES', 'Align data on a 32-byte boundary. This is valid only for object files'],
  0x700000: ['ALIGN_64BYTES', 'Align data on a 64-byte boundary. This is valid only for object files'],
  0x800000: ['ALIGN_128BYTES', 'Align data on a 128-byte boundary. This is valid only for object files'],
  0x900000: ['ALIGN_256BYTES', 'Align data on a 256-byte boundary. This is valid only for object files'],
  0xA00000: ['ALIGN_512BYTES', 'Align data on a 512-byte boundary. This is valid only for object files'],
  0xB00000: ['ALIGN_1024BYTES', 'Align data on a 1024-byte boundary. This is valid only for object files'],
  0xC00000: ['ALIGN_2048BYTES', 'Align data on a 2048-byte boundary. This is valid only for object files'],
  0xD00000: ['ALIGN_4096BYTES', 'Align data on a 4096-byte boundary. This is valid only for object files'],
  0xE00000: ['ALIGN_8192BYTES', 'Align data on a 8192-byte boundary. This is valid only for object files'],
  0x1000000: ['LNK_NRELOC_OVFL', 'The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the VirtualAddress field of the first relocation. It is an error if LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section'],
  0x2000000: ['MEM_DISCARDABLE', 'The section can be discarded as needed'],
  0x4000000: ['MEM_NOT_CACHED', 'The section cannot be cached'],
  0x8000000: ['MEM_NOT_PAGED', 'The section cannot be paged'],
  0x10000000: ['MEM_SHARED', 'The section can be shared in memory'],
  0x20000000: ['MEM_EXECUTE', 'The section can be executed as code'],
  0x40000000: ['MEM_READ', 'The section can be read'],
  0x80000000: ['MEM_WRITE', 'The section can be written to'],
};

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