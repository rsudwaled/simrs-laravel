@extends('adminlte::page')

@section('title', 'SEP Internal')

@section('content_header')
    <h1>SEP Internal</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-md-12">
            @if ($errors->any())
                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </x-adminlte-alert>
            @endif
            <x-adminlte-card title="Pencarian SEP Internal" theme="secondary" collapsible>
                <div class="row">
                    <div class="col-md-6">
                        <form action="" id="myform" method="get">
                            <x-adminlte-input name="nomorsep" label="Nomor SEP" value="{{ $request->nomorsep }}"
                                placeholder="Pencarian Berdasarkan Nomor SEP">
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
            @empty($sepinternals)
                <x-adminlte-alert title="Informasi !" theme="info" dismissable>
                    Silahkan lakukan pencarian berdasarkan NIK atau Nomor Kartu BPJS
                </x-adminlte-alert>
            @else
                @if ($sepinternals->metaData->code != 200)
                    <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                        {{ session()->get('error') }}
                        {{ $sepinternals->metaData->message }}
                    </x-adminlte-alert>
                @else
                    <x-adminlte-card title="Surat Kontrol Peserta" theme="primary" icon="fas fa-info-circle" collapsible>
                        @php
                            $heads = ['Tgl Rujuk Intrn', 'No Rujukan Intrnal', 'No SEP Asal', 'Poli Asal', 'Poli Tujuan', 'Diagnosa', 'Dokter', 'Action'];
                            $config['order'] = ['1', 'DESC'];
                        @endphp
                        <x-adminlte-datatable id="table2" class="nowrap" :heads="$heads" :config="$config" striped bordered
                            hoverable compressed>
                            @if (isset($sepinternals->response->list))
                                @foreach ($sepinternals->response->list as $item)
                                    <tr>
                                        <td>{{ $item->tglrujukinternal }}</td>
                                        <td>{{ $item->nosurat }}</td>
                                        <td>{{ $item->nosep }}</td>
                                        <td>{{ $item->nmpoliasal }}</td>
                                        <td>{{ $item->nmtujuanrujuk }}</td>
                                        <td>{{ $item->diagppk }} {{ $item->nmdiag }}</td>
                                        <td>{{ $item->nmdokter }}</td>
                                        <td>
                                            <form action="{{ route('vclaim.sep_internal_delete') }}"
                                                method="POST">
                                                @csrf
                                                @method('DELETE')
                                                <input type="hidden" name="noSep" value="{{ $item->nosep }}">
                                                <input type="hidden" name="noSurat" value="{{ $item->nosurat }}">
                                                <input type="hidden" name="tglRujukanInternal" value="{{ $item->tglrujukinternal }}">
                                                <input type="hidden" name="kdPoliTuj" value="{{ $item->kdpolituj }}">
                                                <x-adminlte-button class="btn-xs" theme="danger" icon="fas fa-trash-alt"
                                                    type="submit"
                                                    onclick="return confirm('Apakah anda akan menghapus surat kontrol {{ $item->nosurat }} ?')" />
                                            </form>
                                        </td>
                                    </tr>
                                @endforeach
                            @endif
                        </x-adminlte-datatable>
                    </x-adminlte-card>
                @endif
            @endisset
        </div>
    </div>
@stop

{{-- @section('plugins.Select2', true) --}}
@section('plugins.Datatables', true)
