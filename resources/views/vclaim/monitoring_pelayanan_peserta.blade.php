@extends('adminlte::page')

@section('title', 'Monitoring Pelayanan Peserta')

@section('content_header')
    <h1>Monitoring Pelayanan Peserta</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-md-12">
            <x-adminlte-card title="Pencarian Peserta BPJS" theme="secondary" collapsible>
                <div class="row">
                    <div class="col-md-6">
                        <form action="" id="myform" method="get">
                            <x-adminlte-input name="nomorkartu" label="Nomor Kartu" value="{{ $request->nomorkartu }}"
                                placeholder="Pencarian Berdasarkan Nomor Kartu BPJS">
                                <x-slot name="appendSlot">
                                    <x-adminlte-button theme="success" class="withLoad" type="submit" label="Cari!" />
                                </x-slot>
                                <x-slot name="prependSlot">
                                    <div class="input-group-text text-success">
                                        <i class="fas fa-search"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input>
                        </form>
                    </div>
                    <div class="col-md-6">
                        <form action="" id="myform" method="get">
                            <x-adminlte-input name="nik" label="NIK" value="{{ $request->nik }}"
                                placeholder="Pencarian Berdasarkan NIK">
                                <x-slot name="appendSlot">
                                    <x-adminlte-button theme="success" class="withLoad" type="submit" label="Cari!" />
                                </x-slot>
                                <x-slot name="prependSlot">
                                    <div class="input-group-text text-success">
                                        <i class="fas fa-search"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input>
                        </form>
                    </div>
                </div>
            </x-adminlte-card>
        </div>
        @empty($response)
            <div class="col-md-12">
                <x-adminlte-alert title="Informasi !" theme="info" dismissable>
                    Silahkan lakukan pencarian berdasarkan NIK atau Nomor Kartu BPJS
                </x-adminlte-alert>
            </div>
        @else
            <div class="col-md-4">
                <x-adminlte-profile-widget name="{{ $response->response->peserta->nama }}"
                    desc="NIK : {{ $response->response->peserta->nik }}" theme="lightblue" layout-type="classic">
                    <dl class="row">
                        <dt class="col-sm-4">NIK</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->nik }}</dd>
                        <dt class="col-sm-4">No Kartu</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->noKartu }}</dd>
                        <dt class="col-sm-4">No RM</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->mr->noMR }}</dd>
                        <dt class="col-sm-4">No HP</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->mr->noTelepon }}</dd>
                        <dt class="col-sm-4">Nama</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->nama }}</dd>
                        <dt class="col-sm-4">Pisa</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->pisa }}</dd>
                        <dt class="col-sm-4">Jenis Kelamin</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->sex }}</dd>
                        <dt class="col-sm-4">Tanggal Lahir</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->tglLahir }}</dd>
                        <dt class="col-sm-4">Umur</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->umur->umurSekarang }}</dd>
                        <dt class="col-sm-4">Status Peserta</dt>
                        <dd class="col-sm-8">
                            {{ $response->response->peserta->statusPeserta->keterangan }}
                        </dd>
                        <dt class="col-sm-4">Hak Kelas</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->hakKelas->keterangan }}
                        </dd>
                        <dt class="col-sm-4">Jenis Peserta</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->jenisPeserta->keterangan }}
                        </dd>
                        <dt class="col-sm-4">Tgl TAT</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->tglTAT }}</dd>
                        <dt class="col-sm-4">Tgl TMT</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->tglTMT }}</dd>
                        <dt class="col-sm-4">Tgl Cetak Kartu</dt>
                        <dd class="col-sm-8">{{ $response->response->peserta->tglCetakKartu }}</dd>
                    </dl>
                </x-adminlte-profile-widget>
            </div>
            <div class="col-md-8">
                @php
                    $heads = ['Tgl Masuk', 'Tgl Pulang', 'No SEP', 'Action', 'Pasien', 'Pelayanan', 'Poliklinik', 'Diagnosa', 'No Rujukan/Kontrol', 'Status'];
                    $config['order'] = ['0', 'desc'];
                @endphp
                <x-adminlte-card title="SEP Peserta" theme="primary" icon="fas fa-info-circle" collapsible>
                    <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" :config="$config" striped bordered
                        hoverable compressed>
                        @isset($monitoring->response->histori)
                            @foreach ($monitoring->response->histori as $item)
                                <tr>
                                    <td>{{ $item->tglSep }}</td>
                                    <td>{{ $item->tglPlgSep }}</td>
                                    <td>{{ $item->noSep }}</td>
                                    <td>
                                        <form action="{{ route('vclaim.delete_sep', $item->noSep) }}" method="POST">
                                            @csrf
                                            @method('DELETE')
                                            <x-adminlte-button class="btn-xs" theme="danger" icon="fas fa-trash-alt" type="submit"
                                                onclick="return confirm('Apakah anda akan menghapus {{ $item->noSep }} ?')" />
                                        </form>
                                    </td>
                                    <td>
                                        {{ $item->noKartu }} <br>
                                        {{ $item->namaPeserta }}
                                    </td>
                                    <td>
                                        @if ($item->jnsPelayanan == 1)
                                            Rawat Inap
                                        @endif
                                        @if ($item->jnsPelayanan == 2)
                                            Rawat Jalan
                                        @endif
                                        <br>
                                        {{ $item->kelasRawat }}
                                    </td>
                                    <td>
                                        {{ $item->poli }}<br>
                                        {{ $item->ppkPelayanan }}
                                    </td>
                                    <td>{{ $item->diagnosa }}</td>
                                    <td>{{ $item->noRujukan }}</td>
                                    <td>
                                        {{ $item->flag }}
                                        {{ $item->asuransi }}
                                        {{ $item->poliTujSep }}
                                    </td>
                                </tr>
                            @endforeach
                        @endisset
                    </x-adminlte-datatable>
                </x-adminlte-card>
            </div>
            <div class="col-md-6">
                <x-adminlte-card title="Rujukan FKTP Peserta" theme="primary" icon="fas fa-info-circle" collapsible>
                    @php
                        $heads = ['Tgl Rujukan', 'No Rujukan', 'Provider Perujuk', 'Diagnosa', 'Keluhan', 'Tujuan'];
                        $config['order'] = ['0', 'ASC'];
                    @endphp
                    <x-adminlte-datatable id="table2" class="nowrap" :heads="$heads" :config="$config" striped bordered
                        hoverable compressed>
                        @isset($rujukan_peserta)
                            @foreach ($rujukan_peserta as $item)
                                <tr
                                    class="{{ \Carbon\Carbon::parse($item->tglKunjungan)->diffInDays(\Carbon\Carbon::now()) > 90 ? 'text-danger' : null }}">
                                    <td>{{ $item->tglKunjungan }} <br>
                                        {{ \Carbon\Carbon::parse($item->tglKunjungan)->diffInDays(\Carbon\Carbon::now()) > 90 ? 'EXPIRED' : null }}
                                    </td>
                                    <td>{{ $item->noKunjungan }}</td>
                                    <td>
                                        {{ $item->provPerujuk->kode }}<br>
                                        {{ $item->provPerujuk->nama }}
                                    </td>
                                    <td>
                                        {{ $item->diagnosa->kode }}<br>
                                        {{ $item->diagnosa->nama }}
                                    </td>
                                    <td>{{ $item->keluhan }}</td>
                                    <td>
                                        {{ $item->pelayanan->kode }} {{ $item->pelayanan->nama }} <br>
                                        {{ $item->poliRujukan->kode }} {{ $item->poliRujukan->nama }}
                                    </td>
                                </tr>
                            @endforeach
                        @endisset
                    </x-adminlte-datatable>
                </x-adminlte-card>
            </div>
            <div class="col-md-6">
                <x-adminlte-card title="Rujukan RS Peserta" theme="primary" icon="fas fa-info-circle" collapsible>
                    @php
                        $heads = ['Tgl Rujukan', 'No Rujukan', 'Provider Perujuk', 'Diagnosa', 'Keluhan', 'Tujuan'];
                        $config['order'] = ['0', 'ASC'];
                    @endphp
                    <x-adminlte-datatable id="table4" class="nowrap" :heads="$heads" :config="$config" striped bordered
                        hoverable compressed>
                        @isset($rujukan_rs_peserta)
                            @foreach ($rujukan_rs_peserta as $item)
                                <tr>
                                    <td>{{ $item->tglKunjungan }}</td>
                                    <td>{{ $item->noKunjungan }}</td>
                                    <td>
                                        {{ $item->provPerujuk->kode }}<br>
                                        {{ $item->provPerujuk->nama }}
                                    </td>
                                    <td>
                                        {{ $item->diagnosa->kode }}<br>
                                        {{ $item->diagnosa->nama }}
                                    </td>
                                    <td>{{ $item->keluhan }}</td>
                                    <td>
                                        {{ $item->pelayanan->kode }} {{ $item->pelayanan->nama }} <br>
                                        {{ $item->poliRujukan->kode }} {{ $item->poliRujukan->nama }}
                                    </td>
                                </tr>
                            @endforeach
                        @endisset
                    </x-adminlte-datatable>
                </x-adminlte-card>
            </div>
            <div class="col-md-12">
                <x-adminlte-card title="Surat Kontrol Peserta" theme="primary" icon="fas fa-info-circle" collapsible>
                    @php
                        $heads = ['Tgl Kontrol', 'Tgl Terbit', 'No S. Kontrol', 'Action', 'No SEP Asal', 'Poli Asal / Poli Tujuan', 'Dokter', 'Pasien', 'Status'];
                        $config['order'] = ['1', 'DESC'];
                    @endphp
                    <x-adminlte-datatable id="table3" class="nowrap" :heads="$heads" :config="$config" striped bordered
                        hoverable compressed>
                        @isset($suratkontrols)
                            @foreach ($suratkontrols as $item)
                                <tr>
                                    <td>{{ $item->tglRencanaKontrol }}</td>
                                    <td>{{ $item->tglTerbitKontrol }}</td>
                                    <td>
                                        {{ $item->noSuratKontrol }}<br>
                                        {{ $item->jnsPelayanan }} {{ $item->namaJnsKontrol }} ({{ $item->jnsKontrol }})
                                    </td>
                                    <td>
                                        <form action="{{ route('vclaim.delete_surat_kontrol', $item->noSuratKontrol) }}"
                                            method="POST">
                                            @csrf
                                            @method('DELETE')
                                            <x-adminlte-button class="btn-xs" theme="danger" icon="fas fa-trash-alt"
                                                type="submit"
                                                onclick="return confirm('Apakah anda akan menghapus surat kontrol {{ $item->noSuratKontrol }} ?')" />
                                        </form>
                                    </td>
                                    <td>{{ $item->noSepAsalKontrol }}
                                        <br>{{ $item->tglSEP }}
                                    </td>
                                    <td>
                                        {{ $item->poliAsal }} {{ $item->namaPoliAsal }}
                                        <br>{{ $item->poliTujuan }} {{ $item->namaPoliTujuan }}
                                    </td>
                                    <td>{{ $item->kodeDokter }} <br> {{ $item->namaDokter }}
                                    </td>
                                    <td>{{ $item->noKartu }} <br> {{ $item->nama }}
                                    </td>
                                    <td>{{ $item->terbitSEP }}</td>
                                </tr>
                            @endforeach
                        @endisset
                    </x-adminlte-datatable>
                </x-adminlte-card>
            </div>
        @endisset
    </div>
@stop

@section('plugins.Datatables', true)
