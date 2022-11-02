@extends('adminlte::page')

@section('title', 'Edit Permssion')

@section('content_header')
    <h1>Edit Permssion</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            @if ($errors->any())
                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </x-adminlte-alert>
            @endif
            <x-adminlte-card title="Permssion {{ $permission->name }}" theme="secondary">
                <form action="{{ route('admin.permission.store') }}" id="myform" method="post">
                    @csrf
                    <input name="id" value="{{ $permission->id }}" hidden />
                    <x-adminlte-input name="name" value="{{ $permission->name }}" label="Nama" placeholder="Nama Lengkap"
                        enable-old-support />
                </form>
                <x-adminlte-button form="myform" type="submit" theme="success" label="Simpan" />
                <x-adminlte-button theme="danger" label="Kembali" onclick="window.location='{{ url()->previous() }}'" />
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Select2', true)
