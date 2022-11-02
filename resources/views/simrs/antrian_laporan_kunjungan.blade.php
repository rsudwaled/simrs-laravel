@extends('adminlte::page')

@section('title', 'Laporan Kunjungan Poliklinik')

@section('content_header')
    <h1>Laporan Kunjungan Poliklinik</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Filter Data Kunjungan" theme="secondary" collapsible>
                <form action="" method="get">
                    <div class="row">
                        <div class="col-md-3">
                            <x-adminlte-input name="user" label="User" readonly value="{{ Auth::user()->name }}" />
                        </div>
                        <div class="col-md-3">
                            @php
                                $config = ['format' => 'YYYY-MM-DD'];
                            @endphp
                            <x-adminlte-input-date name="tanggal" label="Tanggal Antrian" :config="$config"
                                value="{{ \Carbon\Carbon::parse($request->tanggal)->format('Y-m-d') }}">
                                <x-slot name="prependSlot">
                                    <div class="input-group-text bg-primary">
                                        <i class="fas fa-calendar-alt"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input-date>
                        </div>
                        <div class="col-md-3">
                            @can('admin')
                                <x-adminlte-select2 name="kodepoli" label="Poliklinik">
                                    <option value="">00000 - SEMUA POLIKLINIK</option>
                                    @foreach ($unit as $item)
                                        <option value="{{ $item->KDPOLI }}"
                                            {{ $item->KDPOLI == $request->kodepoli ? 'selected' : null }}>
                                            {{ $item->KDPOLI }}
                                            -
                                            {{ $item->nama_unit }}
                                        </option>
                                    @endforeach
                                </x-adminlte-select2>
                            @else
                                @can('poliklinik')
                                    <x-adminlte-input name="kodepoli" label="Poliklinik" readonly
                                        value="{{ Auth::user()->username }}" />
                                @endcan
                            @endcan
                        </div>
                    </div>
                    <x-adminlte-button type="submit" class="withLoad" theme="primary" label="Submit Antrian" />
                </form>
            </x-adminlte-card>
            @if (isset($kunjungans))
                <div id="printMe">
                    <section class="invoice p-3 mb-3">
                        <div class="row">
                            <img src="{{ asset('vendor/adminlte/dist/img/rswaledico.png') }}" style="width: 100px">
                            <div class="col">
                                <b>RUMAH SAKIT UMUM DAERAH WALED</b><br>
                                <b>KABUPATEN CIREBON</b><br>
                                Jalan Raden Walangsungsang Kecamatan Waled Kabupaten Cirebon 45188<br>
                                www.rsudwaled.id - brsud.waled@gmail.com - Call Center (0231) 661126
                            </div>
                        </div>
                        <div class="row invoice-info">
                            <div class="col-sm-12 invoice-col text-center">
                                <b class="text-lg">SENSUS HARIAN KUNJUNGAN POLIKLINIK</b>
                            </div>
                            <div class="col-sm-4 invoice-col">
                                <dl class="row">
                                    <dt class="col-sm-4 m-0">Poliklinik</dt>
                                    <dd class="col-sm-8 m-0"> :
                                        <b>{{ $unit->firstWhere('KDPOLI', $request->kodepoli)->nama_unit }}</b>
                                    </dd>
                                    <dt class="col-sm-4 m-0">Tanggal</dt>
                                    <dd class="col-sm-8 m-0"> :
                                        <b>{{ \Carbon\Carbon::parse($request->tanggal)->locale('id')->isoFormat('dddd, D MMMM YYYY') }}</b>
                                    </dd>
                                    <dt class="col-sm-4  m-0">User</dt>
                                    <dd class="col-sm-8  m-0"> :
                                        <b>{{ Auth::user()->name }}</b>
                                    </dd>
                                    <dt class="col-sm-4  m-0">Waktu Cetak</dt>
                                    <dd class="col-sm-8  m-0"> :
                                        <b>{{ Carbon\Carbon::now() }}</b>
                                    </dd>
                                </dl>
                            </div>
                        </div>
                        <div class="col-12 table-responsive">
                            <table class="table table-sm text-xs">
                                <thead>
                                    <tr>
                                        <th>No</th>
                                        <th>RM</th>
                                        <th>Nama Pasien</th>
                                        <th>Sex</th>
                                        <th>Umur</th>
                                        <th>Alamat</th>
                                        <th>Pasien</th>
                                        <th>Cara Pembayaran</th>
                                        <th>Kasus</th>
                                        <th>Diagnosa</th>
                                        <th>Tindakan</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    @foreach ($kunjungans as $item)
                                        <tr>
                                            <td>{{ $loop->iteration }}</td>
                                            <td>{{ $item->no_rm }}</td>
                                            <td>{{ $item->pasien->nama_px }}</td>
                                            <td>{{ $item->pasien->jenis_kelamin == 'L' ? 'L' : 'P' }}
                                            </td>
                                            <td>{{ \Carbon\Carbon::parse($item->pasien->tgl_lahir)->age }}</td>
                                            <td>{{ $item->pasien->kecamatans ? $item->pasien->kecamatans->nama_kecamatan : '' }}
                                            </td>
                                            <td>{{ $item->no_sep ? 'JKN' : 'UMUM' }}</td>
                                            <td>{{ $item->penjamin_simrs->nama_penjamin }}
                                            </td>
                                            <td>{{ $item->counter == 1 ? 'BARU' : 'LAMA' }}</td>
                                            <td>{{ $item->diagnosapoli ? $item->diagnosapoli->diag_00 : '' }}</td>
                                            {{-- <td>{{ $response->where('KODE_KUNJUNGAN', $item->kode_kunjungan)->first()->diagx }} --}}
                                            </td>
                                            <td></td>
                                        </tr>
                                    @endforeach
                                </tbody>
                            </table>
                        </div>
                        <div class="row">
                            <div class="col-3 invoice-col table-responsive">
                                <address>
                                    <strong>Berdasarkan Cara Pembayaran</strong>
                                </address>
                                <table class="table table-sm text-xs">
                                    <thead>
                                        <tr>
                                            <th>Pembayaran</th>
                                            <th>Kelompok</th>
                                            <th>Jml</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        @foreach ($kunjungans->groupBy('kode_penjamin') as $key => $item)
                                            <tr>
                                                <td>{{ $penjaminrs->where('kode_penjamin', $key)->first()->nama_penjamin }}
                                                </td>
                                                <td>
                                                    @if ($penjaminrs->where('kode_penjamin', $key)->first()->kode_kelompok == 1)
                                                        BPJS
                                                    @endif
                                                    @if ($penjaminrs->where('kode_penjamin', $key)->first()->kode_kelompok == 2)
                                                        BPJS
                                                    @endif
                                                    @if ($penjaminrs->where('kode_penjamin', $key)->first()->kode_kelompok == 3)
                                                        UMUM
                                                    @endif
                                                    @if ($penjaminrs->where('kode_penjamin', $key)->first()->kode_kelompok == 4)
                                                        DINKES
                                                    @endif
                                                </td>
                                                <td>{{ $item->count() }}</td>
                                            </tr>
                                        @endforeach
                                    </tbody>
                                    <thead>
                                        <tr>
                                            <th colspan="2">Total</th>
                                            <th>{{ $kunjungans->count() }}</th>
                                        </tr>
                                    </thead>
                                </table>
                            </div>
                            <div class="col-3 invoice-col table-responsive">
                                <address>
                                    <strong>Berdasarkan Jenis Pasien</strong>
                                </address>
                                <table class="table table-sm text-xs">
                                    <thead>
                                        <tr>
                                            <th>Jenis</th>
                                            <th>Jml</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>JKN / BPJS</td>
                                            {{-- @foreach ($kunjungans->groupBy('kode_penjamin') as $key => $item)
                                                <td>{{ $penjaminrs->where('kode_penjamin', $key)->first()->nama_penjamin }}
                                                </td>
                                                <td>
                                                    @if ($penjaminrs->where('kode_penjamin', $key)->first()->kode_kelompok == 1)
                                                        BPJS
                                                    @endif
                                                    @if ($penjaminrs->where('kode_penjamin', $key)->first()->kode_kelompok == 2)
                                                        BPJS
                                                    @endif
                                                    @if ($penjaminrs->where('kode_penjamin', $key)->first()->kode_kelompok == 3)
                                                        UMUM
                                                    @endif
                                                    @if ($penjaminrs->where('kode_penjamin', $key)->first()->kode_kelompok == 4)
                                                        DINKES
                                                    @endif
                                                </td>
                                                <td>{{ $item->count() }}</td>
                                            @endforeach --}}
                                            <td>
                                                {{ $kunjungans->where('no_sep', '!=', null)->count() }}
                                            </td>
                                        </tr>
                                        <tr>
                                            <td>Umum</td>
                                            <td>{{ $kunjungans->where('no_sep', null)->count() }}</td>
                                        </tr>
                                    </tbody>
                                    <thead>
                                        <tr>
                                            <th>Total</th>
                                            <th>{{ $kunjungans->count() }}</th>
                                        </tr>
                                    </thead>
                                </table>
                            </div>
                            <div class="col-3 invoice-col table-responsive">
                                <address>
                                    <strong>Berdasarkan Kelamin</strong>
                                </address>
                                <table class="table table-sm text-xs">
                                    <thead>
                                        <tr>
                                            <th>Sex</th>
                                            <th>Jml</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>Laki-Laki</td>
                                            <td>{{ $response->where('jenis_kelaminL', '!=', null)->count() }}</td>
                                        </tr>
                                        <tr>
                                            <td>Perempuan</td>
                                            <td>{{ $response->where('jenis_kelaminP', '!=', null)->count() }}</td>
                                        </tr>
                                    </tbody>
                                    <thead>
                                        <tr>
                                            <th>Total</th>
                                            <th>{{ $kunjungans->count() }}</th>
                                        </tr>
                                    </thead>
                                </table>
                            </div>
                            <div class="col-3 invoice-col table-responsive">
                                <address>
                                    <strong>Berdasarkan Status Pasien</strong>
                                </address>
                                <table class="table table-sm text-xs">
                                    <thead>
                                        <tr>
                                            <th>Status</th>
                                            <th>Jml</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>Baru</td>
                                            <td>{{ $kunjungans->where('counter', '==', 1)->count() }}</td>
                                        </tr>
                                        <tr>
                                            <td>Lama</td>
                                            <td>{{ $kunjungans->where('counter', '!=', 1)->count() }}</td>
                                        </tr>
                                    </tbody>
                                    <thead>
                                        <tr>
                                            <th>Total</th>
                                            <th>{{ $kunjungans->count() }}</th>
                                        </tr>
                                    </thead>
                                </table>
                            </div>
                        </div>
                    </section>
                </div>
                <button class="btn btn-success" onclick="printDiv('printMe')">Print<i class="fas fa-print"></i>
                    Print
                    Laporan</button>
            @endif
        </div>
    </div>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
@section('plugins.DatatablesPlugins', true)
@section('plugins.TempusDominusBs4', true)
@section('js')
    <script>
        function printDiv(divName) {
            var printContents = document.getElementById(divName).innerHTML;
            var originalContents = document.body.innerHTML;
            tampilan_print = document.body.innerHTML = printContents;
            setTimeout('window.addEventListener("load", window.print());', 1000);
        }
    </script>
@endsection
@section('css')
    <style type="text/css" media="print">
        @media print {
            @page {
                size: landscape
            }
        }

        table,
        th,
        td {
            border: 1px solid #333333 !important;
        }
    </style>

@endsection
