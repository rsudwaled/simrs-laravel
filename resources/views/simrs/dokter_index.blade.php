@extends('adminlte::page')

@section('title', 'Referensi Dokter')

@section('content_header')
    <h1>Referensi Dokter</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Data Informasi Dokter" theme="info" icon="fas fa-info-circle" collapsible maximizable>
                @php
                    $heads = ['Kode Dokter', 'Nama Dokter'];
                @endphp
                <x-adminlte-datatable id="table1" :heads="$heads" striped bordered hoverable compressed>
                    @foreach ($dokters as $item)
                        <tr>
                            <td>{{ $item->kodedokter }}</td>
                            <td>{{ $item->namadokter }}</td>
                            {{-- <td>
                                @if ($item->status == 1)
                                    <a href="{{ route('dokter.show', $item->kodedokter) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="aktif" theme="success" />
                                    </a>
                                @else
                                    <a href="{{ route('dokter.show', $item->kodedokter) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="nonaktif" theme="danger" />
                                    </a>
                                @endif
                            </td> --}}
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
                <a href="{{ route('dokter.create') }}" class="btn btn-success">Refresh</a>
            </x-adminlte-card>
            <x-adminlte-card title="Informasi Referensi Dokter" theme="info" icon="fas fa-info-circle" collapsible
                maximizable>
                <x-adminlte-select2 name="dokter" id="dokter" label="Dokter">
                    @foreach ($dokters as $item)
                        <option>{{ $item->kodedokter }} - {{ $item->namadokter }}
                        </option>
                    @endforeach
                </x-adminlte-select2>
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
